import os
from datetime import datetime

def write_summary_log(summary):
    """
    Write a summary log to a file.

    Args:
        summary: The summary of work done in the cursor editor.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Set the log folder path to the specified directory
    log_folder = "/Users/stewart/VSCode/summary_logs"
    # Create the logs directory if it doesn't exist yet
    # exist_ok=True means it won't raise an error if the folder already exists
    os.makedirs(log_folder, exist_ok=True)

    # Create the log file
    # Define the log file path by joining the log folder path with "summary.log" filename
    log_file = os.path.join(log_folder, "summary.log")
    
    # Open the log file in append mode ('a') to add new entries without overwriting
    # Using 'with' ensures the file is properly closed after writing
    with open(log_file, "a") as f:
        # Write a new line containing timestamp and summary
        # The format will be: "2024-01-20 10:30:45 - Some summary text"
        f.write(f"{timestamp} - {summary}\n")

    print(f"Summary log written to {log_file}")

#sample usage
write_summary_log("This is a test summary")