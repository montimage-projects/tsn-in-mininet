import re
import matplotlib.pyplot as plt
import argparse
import numpy as np
import glob
import os

# avoid showing plot window
import matplotlib as mpl
mpl.use('Agg')



def parse_ptp_log(log_file):
    """
    Parses the PTP slave clock log file to extract master offset, frequency offset, and path delay.
    :param log_file: Path to the log file.
    :return: Dictionary with lists of metrics and timestamps.
    """
    # log of ptp slave is different depending "free_running" parameter
    # when free_running = 1, the output is as below
    pattern = '^(.*)ptp4l\[(.+)\]: master offset\s+(-?[0-9]+) s([012]) freq\s+([+-]\d+) path delay\s+(-?\d+)$'
    test_string = 'ptp4l[214733.206]: master offset     -28767 s0 freq  -25546 path delay    130743'

    ## this output is used when free_running = 0
    # pattern = '^(.*)ptp4l\[(.+)\]: rms\s+(-?[0-9]+) max (\d+) freq\s+([+-]\d+) .* delay\s+(-?\d+) .*$'
    # test_string = 'ptp4l[3235037.837]: rms 324564 max 326176 freq -8602326 +/-  77 delay 334763 +/-   0'
    
    data = {
        "timestamp": [],
        "master_offset": [],
        "frequency_offset": [],
        "path_delay": []
    }
    
    # Regular expressions to match the fields
    log_pattern = re.compile(
        pattern,
        re.IGNORECASE
    )
    
    min_ts   =  20
    interval = 320
    
    first_time = 0
    with open(log_file, "r") as file:
        for line in file:
            res = log_pattern.search(line)
            if res:
                time_and_host  = res.group(1)
                kernel_time    = res.group(2)
                master_offset  = res.group(3)
                state          = res.group(4)
                freq           = res.group(5)
                path_delay     = res.group(6)

                #shift X to the first value
                if first_time == 0:
                    first_time = float(kernel_time)
                kernel_time = float(kernel_time) - first_time
                
                # ensure that we plot only in period of [min_ts, interval+min_ts]
                if kernel_time < min_ts:
                    continue
                kernel_time -= min_ts
                if kernel_time > interval:
                    break
         
                data["timestamp"].append(int(kernel_time))
                data["master_offset"].append(float(master_offset))
                data["frequency_offset"].append(float(freq))
                data["path_delay"].append(float(path_delay))
    
    return data

def annotate_boxplot(ax, data):
    """
    Annotates a boxplot with statistical values (mean, median, Q1, Q3).
    :param ax: Matplotlib Axes object.
    :param data: List of values for the boxplot.
    """
    stats = {
        "mean": np.mean(data),
        "median": np.median(data),
        "q1": np.percentile(data, 25),
        "q3": np.percentile(data, 75)
    }
    ax.legend([f"Mean: {stats['mean']:.2f}\n"
                f"Median: {stats['median']:.2f}\n"
                f"Q1: {stats['q1']:.2f}\n"
                f"Q3: {stats['q3']:.2f}"], loc="upper right", fontsize=10)
    
def plot_metrics(data):
    """
    Plots the master offset, frequency offset, and path delay metrics along with boxplots.
    :param data: Dictionary containing timestamps and metric values.
    """
    #plt.figure(figsize=(15, 12))
    #fig, ax = plt.subplots()
    metrics  = ["master_offset", "frequency_offset", "path_delay"]
    y_labels = ["clock offset (ns)", "frequency offset", "path delay (ns)"]
    for i in range(0, len(metrics)):
        plt.clf()
        metric = metrics[i]
        labels = []
        arr    = []
        for label in data:
            labels.append( label )
            arr.append( data[label][metric] )
        # Boxplot for Master Offset (Vertical)
        box = plt.boxplot(arr, vert=True, patch_artist=True, labels=labels, boxprops=dict(color='black', facecolor='black', alpha=0.6), medianprops=dict(color='black'))
        #plt.title("Master Offset Distribution")
        plt.ylabel( y_labels[i] )

        plt.tight_layout()
        plt.grid()
        plt.savefig( f"plot-{metric}.pdf", dpi=30, format='pdf', bbox_inches='tight')


if __name__ == "__main__":
    extension = ".json.slave.log"
    # Set up command-line argument parsing
    log_files = ["1-switch", "2-switches", "5-switches", "10-switches", "20-switches"]
    print(log_files)
    data = dict()
    for name in log_files:
        log_file = f"./{name}{extension}"
        print(f"parsing {name}")
        # Parse the log file
        data[name] = parse_ptp_log(log_file)

    # Plot the metrics
    if len(data):
        plot_metrics(data)
    else:
        print("No valid data found in the log file.")
