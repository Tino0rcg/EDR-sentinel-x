import cv2
import sys

def main():
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("Cannot open webcam")
            sys.exit(1)
        ret, frame = cap.read()
        cap.release()
        if ret:
            print(f"Captured frame of shape {frame.shape}")
        else:
            print("Failed to capture frame")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
