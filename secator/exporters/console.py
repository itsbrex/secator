from secator.exporters._base import Exporter
from secator.rich import console_stdout


class ConsoleExporter(Exporter):
	def send(self):
		results = self.report.data['results']
		for items in results.values():
			for item in items:
				console_stdout.print(item)
