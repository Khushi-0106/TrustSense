from core.scanner import scan_data
from core.recommender import recommend_wipe

scan = scan_data()
print("Scan Result:", scan)

wipe = recommend_wipe(scan)
print("Recommended Wipe:", wipe)