To use on IDA:
import depth_scan
depth_scan.DepthScan(target_function_name)


Format of the output line:
See any return line at DepthScan.calculate_depth(). In depths.txt file, the values are separated by #.
Example of line:
value1#value2#value3

In case of error, the character 'x' is written to the output line.