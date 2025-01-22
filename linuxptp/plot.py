import re
import matplotlib.pyplot as plt
import argparse
import numpy as np

# avoid showing plot window
import matplotlib as mpl
mpl.use('Agg')

def parse_ptp_log(log_file):
    """
    Parses the PTP slave clock log file to extract master offset, frequency offset, and path delay.
    :param log_file: Path to the log file.
    :return: Dictionary with lists of metrics and timestamps.
    """
    
    pattern = '^(.*)ptp4l\[(.+)\]: master offset\s+(-?[0-9]+) s([012]) freq\s+([+-]\d+) path delay\s+(-?\d+)$'
    test_string = 'ptp4l[214733.206]: master offset     -28767 s0 freq  -25546 path delay    130743'

    
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
    plt.figure(figsize=(15, 12))

    # Subplot 1: Master Offset
    plt.subplot(3, 2, 1)
    plt.plot(data["timestamp"], data["master_offset"], label="Master Offset", color="blue")
    plt.title("Master Offset Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Master Offset (ns)")
    plt.grid()
    plt.legend()

    # Boxplot for Master Offset (Vertical)
    ax1 = plt.subplot(3, 2, 2)
    box = plt.boxplot(data["master_offset"], vert=True, patch_artist=True, boxprops=dict(color='black', facecolor='blue', alpha=0.6), medianprops=dict(color='black'))
    plt.title("Master Offset Distribution")
    plt.ylabel("Master Offset (ns)")
    annotate_boxplot(ax1, data["master_offset"])

    # Subplot 2: Frequency Offset
    plt.subplot(3, 2, 3)
    plt.plot(data["timestamp"], data["frequency_offset"], label="Frequency Offset", color="green")
    plt.title("Frequency Offset Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Frequency Offset (PPM)")
    plt.grid()
    plt.legend()

    # Boxplot for Frequency Offset (Vertical)
    ax2 = plt.subplot(3, 2, 4)
    box = plt.boxplot(data["frequency_offset"], vert=True, patch_artist=True, boxprops=dict(facecolor='green', alpha=0.6), medianprops=dict(color='black') )
    plt.title("Frequency Offset Distribution")
    plt.ylabel("Frequency Offset (PPM)")
    annotate_boxplot(ax2, data["frequency_offset"])

    # Subplot 3: Path Delay
    plt.subplot(3, 2, 5)
    plt.plot(data["timestamp"], data["path_delay"], label="Path Delay", color="red")
    plt.title("Path Delay Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Path Delay (ns)")
    plt.grid()
    plt.legend()

    # Boxplot for Path Delay (Vertical)
    ax3 = plt.subplot(3, 2, 6)
    box = plt.boxplot(data["path_delay"], vert=True, patch_artist=True, boxprops=dict(facecolor='red', alpha=0.6), medianprops=dict(color='black'))
    plt.title("Path Delay Distribution")
    plt.ylabel("Path Delay (ns)")
    annotate_boxplot(ax3, data["path_delay"])

    
    plt.tight_layout()
    #plt.show()
    plt.savefig( "output.pdf", dpi=30, format='pdf', bbox_inches='tight')


if __name__ == "__main__":
        # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Parse and plot PTP clock metrics from a log file.")
    parser.add_argument("log_file", help="Path to the PTP log file to parse.")
    
    args = parser.parse_args()

    # Parse the log file
    data = parse_ptp_log(args.log_file)
    
    # Plot the metrics
    if data["timestamp"]:
        plot_metrics(data)
    else:
        print("No valid data found in the log file.")
