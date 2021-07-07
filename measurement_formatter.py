import os
import statistics

input_file = os.path.abspath(os.path.join(os.getcwd(), "measurements.txt"))
result_file = os.path.abspath(os.path.join(os.getcwd(), "result.txt"))
measurements = []
measurement_count = 0


if __name__ == '__main__':
    file = open(input_file, "r")
    lines = file.readlines()

    for line in lines:
        line = line.replace("\n", "")
        if line.isdigit():
            measurement_count += 1
            measurements.append(int(line))

    result_file = open(result_file, "w")
    all_measures = 0

    for m in measurements:
        all_measures += m
        result_file.write(str(m) + ",")

    average = (all_measures/measurement_count)
    standard_dev = statistics.stdev(measurements)
    result_file.write("\nCount: {}".format(measurement_count))
    result_file.write("\nAverage: {}".format(average))
    result_file.write("\nStandard Deviation: {}".format(standard_dev))
