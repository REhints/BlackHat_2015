import os
import sys


def load_ctrees_file(file_path):
	result = []

	with open(file_path) as f:
		lines = f.readlines()

		for ctree_line in lines:
			result.append(ctree_line.strip().split(";"))

	return result


def compare_ctrees(ctrees_1, ctrees_2):
	hashes_normalized = {}
	hashes_not_normalized = {}

	for ctree_tuple in ctrees_1:
		if hashes_normalized.get(ctree_tuple[0]) is not None:
			hashes_normalized[ctree_tuple[0]] += 1
		else:
			hashes_normalized[ctree_tuple[0]] = 1
		
		if hashes_not_normalized.get(ctree_tuple[1]) is not None:
			hashes_not_normalized[ctree_tuple[1]] += 1
		else:
			hashes_not_normalized[ctree_tuple[1]] = 1

	for ctree_tuple in ctrees_2:
		if hashes_normalized.get(ctree_tuple[0]) is not None:
			hashes_normalized[ctree_tuple[0]] -= 1
		else:
			hashes_normalized[ctree_tuple[0]] = -1
		
		if hashes_not_normalized.get(ctree_tuple[1]) is not None:
			hashes_not_normalized[ctree_tuple[1]] -= 1
		else:
			hashes_not_normalized[ctree_tuple[1]] = -1

	return (hashes_normalized, hashes_not_normalized)

def check_hashes(hashes):
	for hash_key in hashes.keys():
		if hashes[hash_key] > 0:
			print "Missing 2 hash " + hash_key, str(hashes[hash_key]) + "\r\n"
		elif hashes[hash_key] < 0:
			print "Missing 1 hash " + hash_key, str(hashes[hash_key]) + "\r\n"
#		elif hashes[hash_key] != 1:
#			print "Incorrect hash " + hash_key, str(hashes[hash_key]) + "\r\n"



if __name__=='__main__':
    if len(sys.argv) < 3:
        print('Usage: sample_dir outfile'.format(sys.argv[0]))
    else:
        ctrees_1 = load_ctrees_file(sys.argv[1])
        ctrees_2 = load_ctrees_file(sys.argv[2])

        hashes_normalized, hashes_not_normalized = compare_ctrees(ctrees_1, ctrees_2)

        print "Checking normalized hashes\r\n"
        check_hashes(hashes_normalized)

        print "Checking not normalized hashes\r\n"
        check_hashes(hashes_not_normalized)