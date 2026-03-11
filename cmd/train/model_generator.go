package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sr79-fw/analyzer"
	"strconv"
	"strings"
)

func main() {
	var completeTrainingVector [][]float64

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.Contains(path, ".csv") {
			vector, err := readDataset(path)
			if err == nil {
				completeTrainingVector = append(completeTrainingVector, vector...)
			}
		}

		return nil
	})
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("Total Training Vectors Loaded: %d\n", len(completeTrainingVector))

	fmt.Println("\\ ---- Training ThreatNet! ---- \\")
	net := analyzer.NewThreatNet([]int{10, 16, 8, 1}, 0.5)

	for _, vector := range completeTrainingVector {
		net.Train(vector[0:10], vector[10])
	}
	fmt.Printf("Training Complete. Saving Training Configurations\n")
	net.SaveWeights("../../weights.json")
}

// readDataset returns an array of input parameters and output for training the
// model. Takes input as the path to the dataset file.
func readDataset(path string) ([][]float64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Index of the parameters we need for the training the ThreatNet.
	// 	"Destination Port":            0,
	// 	"FIN Flag Count":              43,
	// 	"SYN Flag Count":              44,
	// 	"RST Flag Count":              45,
	// 	"PSH Flag Count":              46,
	// 	"ACK Flag Count":              47,
	// 	"URG Flag Count":              48,
	// 	"Total Length of Fwd Packets": 4,
	// 	"Flow Packet/s":               15,

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var trainingVector [][]float64
	var input [11]float64

	// For each record in the total file. Separated as array elements.
	for mainIndex, record := range records {
		if mainIndex > 0 {
			labelIndex := len(record) - 1 // index of the packet's label column.

			// First label the packet's label.
			if record[labelIndex] == "BENIGN" {
				input[10] = 0.0
			} else {
				input[10] = 1.0
			}

			// Destination Port
			input[7], err = strconv.ParseFloat(strings.TrimSpace(record[0]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[7] = normalize(input[7], 1, 65536) // Normalize.

			// Source port is not present in the dataset.
			input[6] = 0.0

			// FIN Flag.
			input[2], err = strconv.ParseFloat(strings.TrimSpace(record[43]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[2] = binarize(input[2])

			// SYN Flag.
			input[0], err = strconv.ParseFloat(strings.TrimSpace(record[44]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[0] = binarize(input[0])

			// RST Flag.
			input[3], err = strconv.ParseFloat(strings.TrimSpace(record[45]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[3] = binarize(input[3])

			// PSH Flag.
			input[4], err = strconv.ParseFloat(strings.TrimSpace(record[46]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[4] = binarize(input[4])

			// ACK Flag.
			input[1], err = strconv.ParseFloat(strings.TrimSpace(record[47]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[1] = binarize(input[1])

			// URG Flag.
			input[5], err = strconv.ParseFloat(strings.TrimSpace(record[48]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[5] = binarize(input[5])

			// Total Length of FWD Packets.
			input[8], err = strconv.ParseFloat(strings.TrimSpace(record[4]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[8] = normalize(input[8], 0, 65535) // Normalize.

			// In cases, where the size is higher than usual.
			// These are edge cases.
			if input[8] > 1.0 {
				input[8] = 1.0
			}
			if input[8] < 0.0 {
				input[8] = 0.0
			}

			// Flow Packet/s.
			input[9], err = strconv.ParseFloat(strings.TrimSpace(record[15]), 64)
			if err != nil {
				fmt.Println(err)
			}
			input[9] = normalize(input[9], 0, 1000) // Normalize.

			// In cases, where packet flow is very high.
			// These are edge cases.
			if input[9] > 1.0 {
				input[9] = 1.0
			}
			if input[9] < 0.0 {
				input[9] = 0.0
			}

			trainingVector = append(trainingVector, input[:])
		}
	}

	return trainingVector, nil
}

func binarize(val float64) float64 {
	if val > 0 {
		return 1.0
	}

	return 0.0
}

// normalize scales the input value to a range between 0.0 and 1.0
// based on the provided lower and upper bounds (Min-Max normalization).
func normalize(value, min, max float64) float64 {
	return ((value - min) / (max - min))
}
