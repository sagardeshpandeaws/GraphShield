class RiskEngine:

    WEIGHTS = {
        "CRITICAL": 10,
        "HIGH": 5,
        "MEDIUM": 3,
        "LOW": 1
    }

    def calculate(self, findings):

        ad_score = 0
        cloud_score = 0

        severity_count = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for finding in findings:

            sev = finding.get("severity", "LOW").upper()
            score = self.WEIGHTS.get(sev, 1)

            severity_count[sev] += 1

            source = str(
                finding.get("source", "")
            ).lower()

            if "azure" in source or "entra" in source:
                cloud_score += score
            else:
                ad_score += score

        total = ad_score + cloud_score

        if total >= 50:
            rating = "CRITICAL"
        elif total >= 30:
            rating = "HIGH"
        elif total >= 15:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        return {
            "ad_score": ad_score,
            "cloud_score": cloud_score,
            "total_score": total,
            "rating": rating,
            "breakdown": severity_count
        }