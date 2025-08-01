from secator.decorators import task
from secator.definitions import (CONFIDENCE, CVSS_SCORE, DELAY, DESCRIPTION,
								 EXTRA_DATA, FOLLOW_REDIRECT, HEADER, ID, IP,
								 MATCHED_AT, NAME, OPT_NOT_SUPPORTED, PERCENT,
								 PROVIDER, PROXY, RATE_LIMIT, REFERENCES,
								 RETRIES, SEVERITY, TAGS, THREADS, TIMEOUT,
								 USER_AGENT, HOST, URL)
from secator.output_types import Progress, Vulnerability
from secator.serializers import JSONSerializer
from secator.tasks._categories import VulnMulti


@task()
class nuclei(VulnMulti):
	"""Fast and customisable vulnerability scanner based on simple YAML based DSL."""
	cmd = 'nuclei'
	input_types = [HOST, IP, URL]
	output_types = [Vulnerability, Progress]
	tags = ['vuln', 'scan']
	file_flag = '-l'
	input_flag = '-u'
	json_flag = '-jsonl'
	input_chunk_size = 20
	opts = {
		'bulk_size': {'type': int, 'short': 'bs', 'help': 'Maximum number of hosts to be analyzed in parallel per template'},  # noqa: E501
		'debug': {'type': str, 'help': 'Debug mode'},
		'exclude_severity': {'type': str, 'short': 'es', 'help': 'Exclude severity'},
		'exclude_tags': {'type': str, 'short': 'etags', 'help': 'Exclude tags'},
		'input_mode': {'type': str, 'short': 'im', 'help': 'Mode of input file (list, burp, jsonl, yaml, openapi, swagger)'},
		'hang_monitor': {'is_flag': True, 'short': 'hm', 'default': True, 'help': 'Enable nuclei hang monitoring'},
		'headless_bulk_size': {'type': int, 'short': 'hbs', 'help': 'Maximum number of headless hosts to be analzyed in parallel per template'},  # noqa: E501
		'new_templates': {'type': str, 'short': 'nt', 'help': 'Run only new templates added in latest nuclei-templates release'},  # noqa: E501
		'automatic_scan': {'is_flag': True, 'short': 'as', 'help': 'Automatic web scan using wappalyzer technology detection to tags mapping'},  # noqa: E501
		'omit_raw': {'is_flag': True, 'short': 'or', 'default': True, 'help': 'Omit requests/response pairs in the JSON, JSONL, and Markdown outputs (for findings only)'},  # noqa: E501
		'response_size_read': {'type': int, 'help': 'Max body size to read (bytes)'},
		'stats': {'is_flag': True, 'short': 'stats', 'default': True, 'help': 'Display statistics about the running scan'},
		'stats_json': {'is_flag': True, 'short': 'sj', 'default': True, 'help': 'Display statistics in JSONL(ines) format'},
		'stats_interval': {'type': str, 'short': 'si', 'help': 'Number of seconds to wait between showing a statistics update'},  # noqa: E501
		'tags': {'type': str, 'help': 'Tags'},
		'templates': {'type': str, 'short': 't', 'help': 'Templates'},
		'template_id': {'type': str, 'short': 'tid', 'help': 'Template id'},
	}
	opt_key_map = {
		HEADER: 'header',
		DELAY: OPT_NOT_SUPPORTED,
		FOLLOW_REDIRECT: 'follow-redirects',
		PROXY: 'proxy',
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retries',
		THREADS: 'c',
		TIMEOUT: 'timeout',
		USER_AGENT: OPT_NOT_SUPPORTED,

		# nuclei opts
		'exclude_tags': 'exclude-tags',
		'exclude_severity': 'exclude-severity',
		'templates': 't',
		'response_size_read': 'rsr'
	}
	opt_value_map = {
		'tags': lambda x: ','.join(x) if isinstance(x, list) else x,
		'templates': lambda x: ','.join(x) if isinstance(x, list) else x,
		'exclude_tags': lambda x: ','.join(x) if isinstance(x, list) else x,
	}
	item_loaders = [JSONSerializer()]
	output_map = {
		Vulnerability: {
			ID: lambda x: nuclei.id_extractor(x),
			NAME: lambda x: nuclei.name_extractor(x),
			DESCRIPTION: lambda x: x['info'].get('description'),
			SEVERITY: lambda x: x['info'][SEVERITY],
			CONFIDENCE: lambda x: 'high',
			CVSS_SCORE: lambda x: x['info'].get('classification', {}).get('cvss-score') or 0,
			MATCHED_AT:  'matched-at',
			IP: 'ip',
			TAGS: lambda x: x['info']['tags'],
			REFERENCES: lambda x: x['info'].get('reference', []),
			EXTRA_DATA: lambda x: nuclei.extra_data_extractor(x),
			PROVIDER: 'nuclei',
		},
		Progress: {
			PERCENT: lambda x: int(x['percent']),
			EXTRA_DATA: lambda x: {k: v for k, v in x.items() if k not in ['percent']}
		}
	}
	install_pre = {
		'*': ['git']
	}
	install_version = 'v3.4.2'
	install_cmd = 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@[install_version]'
	install_github_handle = 'projectdiscovery/nuclei'
	install_post = {
		'*': 'nuclei -ut'
	}
	proxychains = False
	proxy_socks5 = True  # kind of, leaks data when running network / dns templates
	proxy_http = True  # same
	profile = 'cpu'

	@staticmethod
	def id_extractor(item):
		cve_ids = item['info'].get('classification', {}).get('cve-id') or []
		if len(cve_ids) > 0:
			return cve_ids[0]
		return None

	@staticmethod
	def extra_data_extractor(item):
		data = {}
		data['data'] = item.get('extracted-results', [])
		data['type'] = item.get('type', '')
		data['template_id'] = item['template-id']
		data['template_url'] = item.get('template-url', '')
		for k, v in item.get('meta', {}).items():
			data['data'].append(f'{k}: {v}')
		data['metadata'] = item.get('metadata', {})
		return data

	@staticmethod
	def name_extractor(item):
		name = item['template-id']
		matcher_name = item.get('matcher-name', '')
		if matcher_name:
			name += f':{matcher_name}'
		return name
