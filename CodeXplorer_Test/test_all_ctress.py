import os
import sys
import subprocess

def run_ida(path_to_file):
	if os.path.isfile(path_to_file + ".idb"):
		os.remove(path_to_file + ".idb")
	print "Starting ida on %s \r\n" % path_to_file
	subprocess.call(["C:\Program Files (x86)\IDA 6.8\idaq.exe", "-A", "-OHexRaysCodeXplorer:dump_ctrees:dump_types", path_to_file])
	print "Finishing ida\r\n"
	os.remove(path_to_file + ".idb")


def copy_ctrees_file(dirpath, file_hash, suff):
	copy_output_file(dirpath, "ctrees", file_hash, suff)

def copy_types_file(dirpath, file_hash, suff):
	copy_output_file(dirpath, "types", file_hash, suff)

def copy_output_file(dirpath, file_type, file_hash, suff):
	path_to_file_old = os.path.join(dirpath, file_type + ".txt")
	path_to_file_new = os.path.join(dirpath, file_type + "_" + file_hash + "_" + suff + ".txt")
	if os.path.isfile(path_to_file_old):
		os.rename(path_to_file_old, path_to_file_new)
	else:
		print "no " + file_type + ".txt file\r\n"



def main(sample_dir, out_file):
	f = []

	packed = {}

	for (dirpath, dirnames, filenames) in os.walk(sample_dir):
		for file_name in filenames:
			if not file_name.endswith(".idb"):
				run_ida(os.path.join(dirpath, file_name))
				copy_ctrees_file(dirpath, file_name, "1")
				copy_types_file(dirpath, file_name, "1")

				run_ida(os.path.join(dirpath, file_name))
				copy_ctrees_file(dirpath, file_name, "2")
				copy_types_file(dirpath, file_name, "2")
#				break
#			else:
#				os.remove(os.path.join(dirpath, file_name))



if __name__=='__main__':
    if len(sys.argv) < 2:
        print('Usage: sample_dir outfile'.format(sys.argv[0]))
    else:
        main(sys.argv[1], sys.argv[2])