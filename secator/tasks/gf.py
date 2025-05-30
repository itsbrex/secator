from secator.decorators import task
from secator.definitions import OPT_PIPE_INPUT, OPT_NOT_SUPPORTED
from secator.output_types import Tag
from secator.tasks._categories import Tagger


@task()
class gf(Tagger):
	"""Wrapper around grep, to help you grep for things."""
	cmd = 'gf'
	input_types = None  # anything
	output_types = [Tag]
	tags = ['pattern', 'scan']
	file_flag = OPT_PIPE_INPUT
	input_flag = OPT_PIPE_INPUT
	version_flag = OPT_NOT_SUPPORTED
	opts = {
		'pattern': {'type': str, 'help': 'Pattern names to match against (comma-delimited)', 'required': True}
	}
	opt_key_map = {
		'pattern': ''
	}
	install_cmd = (
		'go install -v github.com/tomnomnom/gf@latest && '
		'git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/.gf || true'
	)

	@staticmethod
	def item_loader(self, line):
		yield {'match': line, 'name': self.get_opt_value('pattern').rstrip() + ' pattern'}  # noqa: E731,E501

	@staticmethod
	def on_item(self, item):
		if isinstance(item, Tag):
			item.extra_data = {'source': 'url'}
		return item
