import os
import win32file
import win32con

# Define custom flags
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_EA = 0x00000080
FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800

def monitor_drivers(drive_letter, callback, thread_resume):
    while thread_resume.wait():
        hDir = win32file.CreateFile(
            drive_path,
            1,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        try:
            results = win32file.ReadDirectoryChangesW(
                hDir,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY |
                FILE_NOTIFY_CHANGE_LAST_ACCESS |
                FILE_NOTIFY_CHANGE_CREATION |
                FILE_NOTIFY_CHANGE_EA |
                FILE_NOTIFY_CHANGE_STREAM_NAME |
                FILE_NOTIFY_CHANGE_STREAM_SIZE |
                FILE_NOTIFY_CHANGE_STREAM_WRITE,
                None,
                None
            )
            for action, file in results:
                pathToScan = os.path.join(drive_path, file)
                print(pathToScan)
                callback(pathToScan)  # Call the callback function with only the file path
        except Exception as e:
            print("An error occurred at winmonitor:", e)

    print("RTP waiting to start...")