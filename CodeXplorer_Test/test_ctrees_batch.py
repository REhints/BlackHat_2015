import os
import sys
import operator

hash_stats = {}

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


def process_hash(dirpath, file_hash):
	file_1 = os.path.join(dirpath, "ctrees_" + file_hash + "_1.txt")
	file_2 = os.path.join(dirpath, "ctrees_" + file_hash + "_2.txt")

	ctrees_1 = load_ctrees_file(file_1)
	ctrees_2 = load_ctrees_file(file_2)

	hashes_normalized, hashes_not_normalized = compare_ctrees(ctrees_1, ctrees_2)

	for hash_val in hashes_normalized.keys():
		if hash_stats.get(hash_val) is None:
			hash_stats[hash_val] = [1, [file_hash]]
		else:
			hash_stats[hash_val][0] += 1
			hash_stats[hash_val][1].append(file_hash)

	print "Checking normalized hashes\r\n"
	check_hashes(hashes_normalized)

	print "Checking not normalized hashes\r\n"
	check_hashes(hashes_not_normalized)

def main(sample_dir, out_file):
	test_hashes = set()

	for (dirpath, dirnames, filenames) in os.walk(sample_dir):
		for file_name in filenames:
			if file_name.startswith("ctrees_"):
				file_hash = file_name.split("_")[1]
				if file_hash not in test_hashes:
					process_hash(dirpath, file_hash)
					test_hashes.add(file_hash)

	print sorted(hash_stats.items(), key=operator.itemgetter(1))[10:]

if __name__=='__main__':
	if len(sys.argv) < 2:
		print('Usage: sample_dir outfile'.format(sys.argv[0]))
	else:
		main(sys.argv[1], sys.argv[2])