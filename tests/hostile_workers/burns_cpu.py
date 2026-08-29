"""3. Vòng lặp CPU vô hạn, không bao giờ trả điều khiển."""
n = 0
while True:
    n = (n * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
