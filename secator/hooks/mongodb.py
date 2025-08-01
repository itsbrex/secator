import logging
import time

import pymongo
from bson.objectid import ObjectId
from celery import shared_task

from secator.config import CONFIG
from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug, escape_mongodb_url

# import gevent.monkey
# gevent.monkey.patch_all()

MONGODB_URL = CONFIG.addons.mongodb.url
MONGODB_UPDATE_FREQUENCY = CONFIG.addons.mongodb.update_frequency
MONGODB_CONNECT_TIMEOUT = CONFIG.addons.mongodb.server_selection_timeout_ms
MONGODB_MAX_POOL_SIZE = CONFIG.addons.mongodb.max_pool_size

logger = logging.getLogger(__name__)

_mongodb_client = None


def get_mongodb_client():
	"""Get or create MongoDB client"""
	global _mongodb_client
	if _mongodb_client is None:
		_mongodb_client = pymongo.MongoClient(
			escape_mongodb_url(MONGODB_URL),
			maxPoolSize=MONGODB_MAX_POOL_SIZE,
			serverSelectionTimeoutMS=MONGODB_CONNECT_TIMEOUT,
			connect=False
		)
	return _mongodb_client


def get_runner_dbg(runner):
	"""Runner debug object"""
	return {
		runner.unique_name: runner.status,
		'type': runner.config.type,
		'class': runner.__class__.__name__,
		'caller': runner.config.name,
		**runner.context
	}


def get_results(uuids):
	"""Get results from MongoDB based on a list of uuids.

	Args:
		uuids (list[str | Output]): List of uuids, but can also be a mix of uuids and output types.

	Returns:
		Generator of findings.
	"""
	client = get_mongodb_client()
	db = client.main
	del_uuids = []
	for r in uuids:
		if isinstance(r, tuple(OUTPUT_TYPES)):
			yield r
			del_uuids.append(r)
	uuids = [ObjectId(u) for u in uuids if u not in del_uuids and ObjectId.is_valid(u)]
	for r in db.findings.find({'_id': {'$in': uuids}}):
		finding = load_finding(r)
		yield finding


def update_runner(self):
	client = get_mongodb_client()
	db = client.main
	type = self.config.type
	collection = f'{type}s'
	update = self.toDict()
	chunk = update.get('chunk')
	_id = self.context.get(f'{type}_chunk_id') if chunk else self.context.get(f'{type}_id')
	debug('to_update', sub='hooks.mongodb', id=_id, obj=get_runner_dbg(self), obj_after=True, obj_breaklines=False, verbose=True)  # noqa: E501
	start_time = time.time()
	if _id:
		db = client.main
		start_time = time.time()
		db[collection].update_one({'_id': ObjectId(_id)}, {'$set': update})
		end_time = time.time()
		elapsed = end_time - start_time
		debug(
			f'[dim gold4]updated in {elapsed:.4f}s[/]', sub='hooks.mongodb', id=_id, obj=get_runner_dbg(self), obj_after=False)  # noqa: E501
		self.last_updated_db = start_time
	else:  # sync update and save result to runner object
		runner = db[collection].insert_one(update)
		_id = str(runner.inserted_id)
		if chunk:
			self.context[f'{type}_chunk_id'] = _id
		else:
			self.context[f'{type}_id'] = _id
		end_time = time.time()
		elapsed = end_time - start_time
		debug(f'in {elapsed:.4f}s', sub='hooks.mongodb', id=_id, obj=get_runner_dbg(self), obj_after=False)


def update_finding(self, item):
	if type(item) not in OUTPUT_TYPES:
		return item
	start_time = time.time()
	client = get_mongodb_client()
	db = client.main
	update = item.toDict()
	_type = item._type
	_id = ObjectId(item._uuid) if ObjectId.is_valid(item._uuid) else None
	if _id:
		finding = db['findings'].update_one({'_id': _id}, {'$set': update})
		status = 'UPDATED'
	else:
		finding = db['findings'].insert_one(update)
		item._uuid = str(finding.inserted_id)
		status = 'CREATED'
	end_time = time.time()
	elapsed = end_time - start_time
	debug_obj = {
		_type: status,
		'type': 'finding',
		'class': self.__class__.__name__,
		'caller': self.config.name,
		**self.context
	}
	debug(f'in {elapsed:.4f}s', sub='hooks.mongodb', id=str(item._uuid), obj=debug_obj, obj_after=False)  # noqa: E501
	return item


def find_duplicates(self):
	from secator.celery import IN_CELERY_WORKER_PROCESS
	ws_id = self.toDict().get('context', {}).get('workspace_id')
	if not ws_id:
		return
	if not IN_CELERY_WORKER_PROCESS:
		tag_duplicates(ws_id)
	else:
		tag_duplicates.delay(ws_id)


def load_finding(obj):
	finding_type = obj['_type']
	klass = None
	for otype in OUTPUT_TYPES:
		if finding_type == otype.get_name():
			klass = otype
			item = klass.load(obj)
			item._uuid = str(obj['_id'])
			return item
	return None


def load_findings(objs):
	findings = [load_finding(obj) for obj in objs]
	return [f for f in findings if f is not None]


@shared_task
def tag_duplicates(ws_id: str = None, full_scan: bool = False):
	"""Tag duplicates in workspace.

	Args:
		ws_id (str): Workspace id.
		full_scan (bool): If True, scan all findings, otherwise only untagged findings.
	"""
	debug(f'running duplicate check on workspace {ws_id}', sub='hooks.mongodb')
	init_time = time.time()
	client = get_mongodb_client()
	db = client.main
	start_time = time.time()
	workspace_query = {'_context.workspace_id': str(ws_id), '_context.workspace_duplicate': False, '_tagged': True}
	untagged_query = {'_context.workspace_id': str(ws_id), '_tagged': {'$ne': True}}
	if full_scan:
		del untagged_query['_tagged']
	workspace_findings = load_findings(list(db.findings.find(workspace_query).sort('_timestamp', -1)))
	untagged_findings = load_findings(list(db.findings.find(untagged_query).sort('_timestamp', -1)))
	debug(
		f'Workspace non-duplicates findings: {len(workspace_findings)}, '
		f'Untagged findings: {len(untagged_findings)}. '
		f'Query time: {time.time() - start_time}s',
		sub='hooks.mongodb'
	)
	start_time = time.time()
	seen = []
	db_updates = {}

	for item in untagged_findings:
		if item._uuid in seen:
			continue

		debug(
			f'Processing: {repr(item)} ({item._timestamp}) [{item._uuid}]',
			sub='hooks.mongodb',
			verbose=True
		)

		duplicate_ids = [
			_._uuid
			for _ in untagged_findings
			if _ == item and _._uuid != item._uuid
		]
		seen.extend(duplicate_ids)

		debug(
			f'Found {len(duplicate_ids)} duplicates for item',
			sub='hooks.mongodb',
			verbose=True
		)

		duplicate_ws = [
			_ for _ in workspace_findings
			if _ == item and _._uuid != item._uuid
		]
		print(f' --> Found {len(duplicate_ws)} workspace duplicates for item')

		related_ids = []
		if duplicate_ws:
			duplicate_ws_ids = [_._uuid for _ in duplicate_ws]
			duplicate_ids.extend(duplicate_ws_ids)
			for related in duplicate_ws:
				related_ids.extend(related._related)

		print(f' --> Found {len(duplicate_ids)} total duplicates for item')

		db_updates[item._uuid] = {
			'_related': duplicate_ids + related_ids,
			'_context.workspace_duplicate': False,
			'_tagged': True
		}
		for uuid in duplicate_ids:
			db_updates[uuid] = {
				'_context.workspace_duplicate': True,
				'_tagged': True
			}

	print(f'Finished processing untagged findings in {time.time() - start_time}s')
	start_time = time.time()

	debug(f'Executing {len(db_updates)} database updates', sub='hooks.mongodb')
	from pymongo import UpdateOne
	if not db_updates:
		print('no db updates to execute')
		return

	result = db.findings.bulk_write(
		[UpdateOne({'_id': ObjectId(uuid)}, {'$set': update}) for uuid, update in db_updates.items()]
	)
	print(result)
	print(f'Finished running db update in {time.time() - start_time}s')
	print(f'Finished running tag duplicates in {time.time() - init_time}s')


@shared_task
def tag_duplicates_old(ws_id: str = None, full_scan: bool = False):
	"""Tag duplicates in workspace.

	Args:
		ws_id (str): Workspace id.
		full_scan (bool): If True, scan all findings, otherwise only untagged findings.
	"""
	debug(f'running duplicate check on workspace {ws_id}', sub='hooks.mongodb')
	client = get_mongodb_client()
	db = client.main
	workspace_query = list(
		db.findings.find({'_context.workspace_id': str(ws_id), '_tagged': True}).sort('_timestamp', -1))
	untagged_query = {'_context.workspace_id': str(ws_id)}
	if not full_scan:
		untagged_query['_tagged'] = {'$ne': True}
	untagged_query = list(
		db.findings.find(untagged_query).sort('_timestamp', -1))
	if not untagged_query:
		debug('no untagged findings. Skipping.', id=ws_id, sub='hooks.mongodb')
		return
	debug(f'found {len(untagged_query)} untagged findings', id=ws_id, sub='hooks.mongodb')

	untagged_findings = load_findings(untagged_query)
	workspace_findings = load_findings(workspace_query)
	non_duplicates = []
	duplicates = []
	for item in untagged_findings:
		# If already seen in duplicates
		seen = [f for f in duplicates if f._uuid == item._uuid]
		if seen:
			continue

		# Check for duplicates
		tmp_duplicates = []

		# Check if already present in list of workspace_findings findings, list of duplicates, or untagged_findings
		workspace_dupes = [f for f in workspace_findings if f == item and f._uuid != item._uuid]
		untagged_dupes = [f for f in untagged_findings if f == item and f._uuid != item._uuid]
		seen_dupes = [f for f in duplicates if f == item and f._uuid != item._uuid]
		tmp_duplicates.extend(workspace_dupes)
		tmp_duplicates.extend(untagged_dupes)
		tmp_duplicates.extend(seen_dupes)
		debug(
			f'for item {item._uuid}',
			obj={
				'workspace dupes': len(workspace_dupes),
				'untagged dupes': len(untagged_dupes),
				'seen dupes': len(seen_dupes)
			},
			id=ws_id,
			sub='hooks.mongodb',
			verbose=True)
		tmp_duplicates_ids = list(dict.fromkeys([i._uuid for i in tmp_duplicates]))
		debug(f'duplicate ids: {tmp_duplicates_ids}', id=ws_id, sub='hooks.mongodb', verbose=True)

		# Update latest object as non-duplicate
		if tmp_duplicates:
			duplicates.extend([f for f in tmp_duplicates])
			db.findings.update_one({'_id': ObjectId(item._uuid)}, {'$set': {'_related': tmp_duplicates_ids}})
			debug(f'adding {item._uuid} as non-duplicate', id=ws_id, sub='hooks.mongodb', verbose=True)
			non_duplicates.append(item)
		else:
			debug(f'adding {item._uuid} as non-duplicate', id=ws_id, sub='hooks.mongodb', verbose=True)
			non_duplicates.append(item)

	# debug(f'found {len(duplicates)} total duplicates')

	# Update objects with _tagged and _duplicate fields
	duplicates_ids = list(dict.fromkeys([n._uuid for n in duplicates]))
	non_duplicates_ids = list(dict.fromkeys([n._uuid for n in non_duplicates]))

	search = {'_id': {'$in': [ObjectId(d) for d in duplicates_ids]}}
	update = {'$set': {'_context.workspace_duplicate': True, '_tagged': True}}
	db.findings.update_many(search, update)

	search = {'_id': {'$in': [ObjectId(d) for d in non_duplicates_ids]}}
	update = {'$set': {'_context.workspace_duplicate': False, '_tagged': True}}
	db.findings.update_many(search, update)
	debug(
		'completed duplicates check for workspace.',
		id=ws_id,
		obj={
			'processed': len(untagged_findings),
			'duplicates': len(duplicates_ids),
			'non-duplicates': len(non_duplicates_ids)
		},
		sub='hooks.mongodb')


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner]
	}
}
