from argparse import ArgumentParser
from modules import scanners

parser = ArgumentParser()
parser.add_argument(
    "-sn",
    help="disable port scanning",
    action="store_true"
)
parser.add_argument("-sS", help="TCP SYN scan", action="store_true")
parser.add_argument("-sT", help="TCP connect scan", action="store_true")
parser.add_argument("-sN", help="TCP SYN scan", action="store_true")
