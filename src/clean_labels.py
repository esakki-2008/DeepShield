
def clean_label(label):
    """Normalize attack labels without changing their meaning."""

    label = str(label).strip()

    label_mapping = {
        "Web Attack � Brute Force": "Web Attack - Brute Force",
        "Web Attack � XSS": "Web Attack - XSS",
        "Web Attack � Sql Injection": "Web Attack - Sql Injection",
    }

    return label_mapping.get(label, label)


# Test the function
test_labels = [
    "BENIGN",
    "Web Attack � Brute Force",
    "Web Attack � XSS",
    "Web Attack � Sql Injection",
    "DDoS"
]

for label in test_labels:
    print(label, "->", clean_label(label))
