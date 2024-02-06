import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Define the provided functions
def calculate_statistics(data):
    median = int(data['MedianTime'].median())
    mean = data['MedianTime'].mean()
    q1 = int(data['MedianTime'].quantile(0.25))
    q3 = int(data['MedianTime'].quantile(0.75))
    return median, mean, q1, q3

def print_statistics(label, stats):
    median, mean, q1, q3 = stats
    print(f"{label} Statistics:")
    print(f"  Median: {median}")
    print(f"  Mean: {mean:.2f}")
    print(f"  Q1: {q1}")
    print(f"  Q3: {q3}")
    print()  # Adds an empty line for better separation

def plot_box_and_cdf(data_dualstack, data_clat, data_v6only, data_v6only_slow, title_prefix, save_path_prefix):
    # Function to create box plot
    def create_box_plot(log_scale=False):
        plt.figure(figsize=(10, 6))
        boxplot_elements = plt.boxplot([data_dualstack['MedianTime'], data_clat['MedianTime'], data_v6only['MedianTime'], data_v6only_slow['MedianTime']],
                                       labels=['Dualstack', 'CLAT', 'v6only-capable', 'v6only-capable Slow'],
                                       showfliers=False, patch_artist=True)
        # Annotating the median, first quartile (Q1), and third quartile (Q3) for each box
        num_boxes = len(boxplot_elements['boxes'])
        for i in range(num_boxes):
            box = boxplot_elements['boxes'][i]
            median = boxplot_elements['medians'][i]
            box_coords = box.get_path().vertices
            q1_y = box_coords[0, 1]
            q3_y = box_coords[2, 1]
            median_y = median.get_ydata()[0]
            box_x = box_coords[0, 0]

            plt.text(box_x, q1_y, f'{int(q1_y)}',
                    verticalalignment='top', fontsize=8,
                    bbox=dict(facecolor='white', alpha=0.5))
            plt.text(box_x, q3_y, f'{int(q3_y)}',
                    verticalalignment='bottom', fontsize=8,
                    bbox=dict(facecolor='white', alpha=0.5))
            plt.text(box_x, median_y, f'{int(median_y)}',
                    verticalalignment='center', fontsize=8,
                    bbox=dict(facecolor='white', alpha=0.5))

        if log_scale:
            plt.yscale('log')
            plt.ylim(70, 500)
            plt.title(f'{title_prefix} - Box Plot (Log Scale)')
            plt.ylabel('RTT (ms) - Log Scale')
            plt.savefig(f'{save_path_prefix}_BoxPlot_LogScale.png')
        else:
            plt.ylim(0, 360)
            plt.title(f'{title_prefix} - Box Plot')
            plt.ylabel('RTT (ms)')
            plt.savefig(f'{save_path_prefix}_BoxPlot.png')
        plt.close()

    # Function to create CDF plot
    def create_cdf_plot(log_scale=False):
        plt.figure(figsize=(10, 6))
        for data, label in zip([data_dualstack, data_clat, data_v6only, data_v6only_slow], ['Dualstack', 'CLAT', 'v6only-capable', 'v6only-capable Slow']):
            sorted_data = np.sort(data['MedianTime'])
            yvals = np.arange(len(sorted_data)) / float(len(sorted_data) - 1)
            plt.plot(sorted_data, yvals, label=label)

        if log_scale:
            plt.xscale('log')
            plt.xlim(10, 900)
            plt.title(f'{title_prefix} - CDF (Log Scale)')
            plt.xlabel('RTT (ms) - Log Scale')
        else:
            plt.xlim(0, 350)
            plt.title(f'{title_prefix} - CDF')
            plt.xlabel('RTT (ms)')
        
        plt.ylim(0, 1)
        plt.ylabel('Cumulative Probability')
        plt.legend()
        plt.savefig(f'{save_path_prefix}_CDF{"_LogScale" if log_scale else ""}.png')
        plt.close()

    # Create and save each of the four plots
    create_box_plot(log_scale=True)
    create_box_plot(log_scale=False)
    create_cdf_plot(log_scale=True)
    create_cdf_plot(log_scale=False)


# Function to read data from a file
def read_data(file_path):
    with open(file_path, 'r') as file:
        data = file.readlines()
    data = [int(line.strip()) for line in data]
    return pd.DataFrame(data, columns=['MedianTime'])

# Read data from files
data_clat = read_data('twitter1/query_times_CLAT.log')
data_dualstack = read_data('twitter1/query_times_DualStack.log')
data_v6only = read_data('twitter1/query_times_IPv6-only-capable.log')
data_v6only_slow = read_data('twitter1/query_times_IPv6-only-capable_slow.log')

# Calculate statistics for each dataset
stats_clat = calculate_statistics(data_clat)
stats_dualstack = calculate_statistics(data_dualstack)
stats_v6only = calculate_statistics(data_v6only)
stats_v6only_slow = calculate_statistics(data_v6only_slow)

print_statistics("CLAT", stats_clat)
print_statistics("DualStack", stats_dualstack)
print_statistics("IPv6-only-capable", stats_v6only)
print_statistics("IPv6-only-capable Before code change", stats_v6only_slow)

# Plot and save the box plot and CDF graphs
plot_box_and_cdf(data_dualstack, data_clat, data_v6only, data_v6only_slow, "Twitter Analysis", "twitter1/twitter_analysis")

