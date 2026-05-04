from core.scanner import scan_data
from core.recommender import recommend_wipe

from processing.wipe import simulate_wipe
from processing.trust_score import calculate_trust_score
from processing.certificate import generate_certificate

from security.verification import store_certificate, verify_certificate
from security.attack_simulation import simulate_attack


def main():
    print("\n===== TrustSense System Starting =====\n")

    # STEP 1: Scan System
    scan_result = scan_data()
    print("🔍 Scan Result:", scan_result)

    # STEP 2: Recommend Wipe
    wipe_plan = recommend_wipe(scan_result)
    print("🧠 Recommended Wipe:", wipe_plan)

    # STEP 3: Perform Wipe
    wipe_status = simulate_wipe(wipe_plan["wipe_level"])
    print("🧹 Wipe Status:", wipe_status)

    # STEP 4: Calculate Trust Score
    trust_score = calculate_trust_score(scan_result, wipe_plan)
    print("📊 Trust Score:", trust_score)

    # STEP 5: Generate Certificate
    certificate = generate_certificate(
    "Device123",                      # device_id (dummy for now)
    trust_score["trust_score"],       # actual score
    wipe_plan["wipe_level"]           # string value
)

    # STEP 6: Store Certificate (Ledger)
    store_certificate(certificate)

    # STEP 7: Verify Certificate
    is_valid = verify_certificate(certificate)
    print("✅ Certificate Verification:", is_valid)

    # STEP 8: Simulate Attack
    attack_result = simulate_attack()
    print("⚠️ Attack Simulation Result:", attack_result)

    print("\n===== TrustSense Execution Complete =====\n")


if __name__ == "__main__":
    main()