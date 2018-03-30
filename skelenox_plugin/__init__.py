
import logging
g_logger = logging.getLogger()
for h in g_logger.handlers:
    g_logger.removeHandler(h)

g_logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
format_str = '[%(asctime)s] [%(levelname)s] [%(threadName)s]: %(message)s'
formatter = logging.Formatter(format_str, datefmt='%d/%m/%Y %I:%M:%S')
handler.setFormatter(formatter)
g_logger.addHandler(handler)
