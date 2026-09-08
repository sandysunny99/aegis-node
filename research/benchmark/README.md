# Aegis Node Benchmark Dataset

## Purpose
This dataset is designed to evaluate the performance and accuracy of the Aegis Node scanner against a variety of file formats and contents, including benign files, malware references, malicious payloads, and edge cases.

## Categories
- **A**: Benign data
- **B**: Malware references (Threat Intel)
- **C**: Malicious / Suspicious payloads
- **D**: Formula injection
- **E**: Prompt injection
- **F**: Encoded content
- **G**: Mixed content
- **H**: Edge cases (empty, malformed, unicode, long fields)

## Methodology
- Files in the benchmark dataset are evaluated by the scanner.
- The results are compared against the expected classification defined in `ground_truth.json`.
- The metrics generated reflect true positive, false positive, true negative, and false negative rates across multiple threat categories.

## Limitations
- Synthetic data may not capture all the nuances of real-world targeted attacks.
- Some edge cases like extremely large files or highly nested archives are out of scope for this specific synthetics benchmark.
