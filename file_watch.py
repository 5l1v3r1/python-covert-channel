import sys
from time import sleep
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class NewFileHandler(FileSystemEventHandler):
	def on_created(self, event):
		print(event.src_path)


def main():
	event_handler = NewFileHandler()
	observer = Observer()
	observer.schedule(event_handler, '.', recursive=True)
	observer.start()

	try:
		while True:
			sleep(1)
	except KeyboardInterrupt:
		observer.stop()
	observer.join()


if __name__ == '__main__':
	main()