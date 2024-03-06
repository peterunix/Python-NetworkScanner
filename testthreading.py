import threading
import time

# Define a function that will be executed by the thread
def print_numbers():
    for i in range(5):
        print(i)
        time.sleep(1)  # Sleep for 1 second

# Create a new thread
thread = threading.Thread(target=print_numbers)

# Start the thread
thread.start()

# Main thread continues execution
for i in range(5):
    print("Main thread:", i)
    time.sleep(0.5)  # Sleep for 0.5 seconds

# Wait for the thread to finish execution
thread.join()

print("Thread execution finished")