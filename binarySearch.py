class BinarySearch:
    @staticmethod
    def search(arr, target):
        left, right = 0, len(arr) - 1
        while left <= right:
            mid = (left + right) // 2
            if arr[mid] == target:
                return mid  
            elif arr[mid] < target:
                left = mid + 1
            else:
                right = mid - 1
        return -1  
arr = [10, 20, 30, 40, 50]
index = BinarySearch.search(arr, 30)
if index != -1:
    print(f"Element found at index {index}")
else:
    print("Element not found")