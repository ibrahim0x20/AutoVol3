import os
from volatility3.framework import contexts
from volatility3.framework import exceptions
from volatility3.framework import interfaces

def generate_csv_from_memory_image(directory_path, csv_file):
    try:
        # Check if the provided directory path exists
        if not os.path.exists(directory_path):
            print(f"The directory '{directory_path}' does not exist.")
            return

        # Check if there are any .img files in the directory
        img_files = [file for file in os.listdir(directory_path) if file.endswith(".img")]

        if not img_files:
            print(f"No '.img' files found in '{directory_path}'.")
            return

        # Create a context
        context = contexts.Context()

        # Set the base configuration path
        context.base_config_path = os.path.join("plugins", "windows", csv_file[:-4])

        # Set the file scan attribute to use the first .img file
        context.config['file_scan'] = img_files[0]

        # Load the appropriate plugin based on the CSV file name
        plugin_name = csv_file[:-4]  # Remove the ".csv" extension
        plugin = context.load_plugin(plugin_name)

        # Create an output writer for the CSV file
        output_writer = interfaces.plugins.FileInterface(context, plugin)

        # Run the plugin
        plugin.run()

        # Get the result and write it to the CSV file
        result = output_writer.data
        with open(csv_file, 'w') as csv_output:
            csv_output.write(result)

        return True

    except PermissionError:
        print(f"You do not have permission to access '{directory_path}'.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    return False

# List of CSV files to generate
csv_files = ['pslist.csv', 'psscan.csv', 'pstree.csv', 'dlllist.csv', 'cmdline.csv', 'netstat.csv', 'netscan.csv', 'handles.csv']

# Specify the directory path you want to list files from
directory_path = "./memory"

# Loop through and generate CSV files
for csv_file in csv_files:
    success = generate_csv_from_memory_image(directory_path, csv_file)
    if success:
        print(f"Generated file: {csv_file}")

# Usage example:
# generate_csv_from_memory_image(directory_path, 'dlllist.csv')
