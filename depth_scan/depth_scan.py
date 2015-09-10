# Based on https://code.google.com/p/idapathfinder/

import idc
import idautils

class DepthScan(object):

	def __init__(self, destination):
		# Get EntryPoint name
		try:
			epAddr = idc.BeginEA()
			self.epName = idc.GetFunctionName(epAddr)
		except:
			self.epName = ""
		
		# Get result
		retval = None
		try:
			retval = self.calculate_depth(destination, True)
		except:
			retval = None
		
		# Write the results to a file
		with open("depth.txt", "a") as fp:
			if retval == None:
				fp.write("x\n")
			else:
				fp.write("%d#%d#%d#%d#%d#%d#%d#%d#%d#%s#%d\n" % retval)

	def __enter__(self):
		return self
		
	def __exit__(self, t, v, traceback):
		return

	def calculate_depth(self, name, only_code):
		MAX_NODES = 100
		
		depth = -1
		nodes_counter = 0
		epFound = 0
		nParents = -1
		nParentsCode = -1
		first_root_depth = -1
		last_root_depth = -1
		first_data_depth = -1
		max_nodes_limit_reached = 0
		first_blank_depth = -1
		target_function_name = None
		
		visited_nodes = []
		names = []
		
		new_names_len = None
		
		# Since we only analyze named addresses/xrefs, exit now if the target function is not named
		if not name:
			print "  Name is None or an empty string: #%s#" % str(name)
			return None
		
		target_function_name = name
		
		# Some initializations
		visited_nodes.append(name)
		names.append(name)
		
		# Get number of parents of the target function
		try:
			nParents = len([x for x in idautils.XrefsTo(idc.LocByName(name)) if x.type != 21])
		except:
			nParents = -1
		
		# Get number of code-only parents of the target function
		try:
			nParentsCode = len([x for x in idautils.XrefsTo(idc.LocByName(name)) if x.type != 21 and x.iscode == 1])
		except:
			nParentsCode = -1

		while names:
			new_names = []
			depth += 1

			#print "names: %s" % str(names)
			for name in names:
				# Finish the analysis if we reached the limit. Increment nodes_counter
				if nodes_counter >= MAX_NODES:
					max_nodes_limit_reached = 1
					print "  Max nodes limit reached: %d   depth = %d" % (nodes_counter, depth)
					return (depth, epFound, first_root_depth, last_root_depth, first_data_depth, first_blank_depth, nParents, nParentsCode, max_nodes_limit_reached, target_function_name, nodes_counter)
				nodes_counter += 1
				
				# If we reached the entrypoint, then we are done
				if name == self.epName:
					epFound = 1
					print "  Entry point found. depth %d" % depth
					return (depth, epFound, first_root_depth, last_root_depth, first_data_depth, first_blank_depth, nParents, nParentsCode, max_nodes_limit_reached, target_function_name, nodes_counter)
				
				is_root = True
				for reference in [x for x in idautils.XrefsTo(idc.LocByName(name)) if x.type != 21]:
					reference_name = idc.GetFunctionName(reference.frm)
					
					# We are only interested in named addresses/xrefs
					if not reference_name:
						if first_blank_depth == -1:
							print "Found first blank name at depth %d" % depth
							first_blank_depth = depth
						continue
					
					#print "  reference: %s" % reference_name
					
					is_root = False
					
					# Get depth of the first node with a data node as a parent
					if first_data_depth == -1 and reference.iscode != 1:
						print "  Found first data at depth %d" % depth
						first_data_depth = depth
					
					# If only_code is True, then we will only analyze code xrefs
					if only_code and reference.iscode != 1:
						continue
					
					if reference_name not in visited_nodes:
						visited_nodes.append(reference_name)
						new_names.append(reference_name)
					
				if is_root:
					print "  Found a root node at depth %d" % depth
					
					if first_root_depth == -1:
						print "  Found first root at depth %d" % depth
						first_root_depth = depth
					
					last_root_depth = depth
			
			names = new_names
		
		print "Function end    depth %d" % depth
		return (depth, epFound, first_root_depth, last_root_depth, first_data_depth, first_blank_depth, nParents, nParentsCode, max_nodes_limit_reached, target_function_name, nodes_counter)

