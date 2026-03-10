package analyzer

import (
	"encoding/json"
	"math"
	"math/rand"
	"os"
)

// ---- CLASSIFIER SPECIFIC TYPES ---- //
type VectorInt []int
type VectorFloat []float64
type Matrix [][]float64
type Layer [][][]float64

// dot performs the dot matrix of two matrices 'a' and 'b' and
// and modified the 'a' (caller) in place.
func (a *Matrix) dot(b *Matrix) {
	rowA := len(*a)      // Rows of the resulting matrix.
	colA := len((*a)[0]) //
	colB := len((*b)[0]) // Columns of the resulting matrix.

	finalMatrix := make(Matrix, rowA) // for each row of new matrix.
	for i := range finalMatrix {
		finalMatrix[i] = make(VectorFloat, colB)
		for j := 0; j < colB; j++ { // for each column of new matrix.
			for k := 0; k < colA; k++ { // Number of elements to multiply on each round.
				finalMatrix[i][j] += (*a)[i][k] * (*b)[k][j]
			}
		}
	}

	// mutate the original (caller) matrix.
	*a = finalMatrix
}

func (m *Matrix) transpose() *Matrix {
	rows := len(*(m))
	columns := len((*m)[0])

	// Initialize the new Matrix in transposed configuration.
	result := make(Matrix, columns)
	// This is important, here!! This ensures the matrix is
	// properly configured.
	for j := 0; j < columns; j++ {
		result[j] = make(VectorFloat, rows)
	}

	for i := 0; i < rows; i++ {
		for j := 0; j < columns; j++ {
			result[j][i] = (*m)[i][j]
		}
	}

	return &result
}

// ThreatNet structure.
type ThreatNet struct {
	// e.g., Topology: [2, 3, 2, 1]
	topology VectorInt

	// weights: [Encapsulating Array][Neuron][Weights/Neuron]
	// Representation: [ input --> hiddenLayer1: [ [a, b, c] [d, e, f] ], hiddenLayer1 --> hiddenLayer2: [ [a, b] [c, d] [e, f] ] hiddenLayer2 --> output: [ [a] [b] ] ]
	weights   Layer // slice of weight matrices
	threshold float64
}

// NewThreatNet is constructor for the ThreatNet. Accepts topology config
// and user defined threshold
func NewThreatNet(topology []int, threshold float64) *ThreatNet {
	net := &ThreatNet{
		topology:  topology,
		threshold: threshold,
	}

	// Initialize the weights.
	initializeThreatNetWeights(net)

	return net
}

// initializeThreatNetWeights populates the ThreatNet's weight
// layers with random float64 values.
// How this works? Given a topology such as [2, 3, 2, 1]:
// Input Layer: topology[0] (2 nodes).
// Output Layer: topology[3] (1 node).
// The Iteration Process:
// Outer Loop (i): Iterates through the layers, starting at the first hidden layer.
// Middle Loop (j): Iterates through the nodes of the previous layer (i-1).
// Inner Loop (k): Iterates through the nodes of the current layer (i),
// appending the generated weights to the weight slice.
// As the iterations proceed from bottom to top, append each layer to the previous arrays.
func initializeThreatNetWeights(net *ThreatNet) {
	for i := 0; i < len(net.topology)-1; i++ {
		// Matrix representation of weights from previous layer to next layer.
		layer := make(Matrix, net.topology[i])
		// ---- Previous Hidden Layer/First Layer ---- //
		for j := 0; j < net.topology[i]; j++ {

			// Weights are pushed in this slice.
			subLayer := make(VectorFloat, net.topology[i+1])

			// ---- Current Hidden Layer/Next Hidden Layer ---- //
			for k := 0; k < net.topology[i+1]; k++ {
				subLayer[k] = rand.Float64()
			}
			layer[j] = subLayer
		}

		// Attach the Layer Matrix for a particular iteration.
		net.weights = append(net.weights, layer)
	}
}

// sigmoid squashes any value to range 0.0 and 1.0 (both included).
func (net *ThreatNet) sigmoid(x float64) float64 {
	return (1 / (1 + math.Exp(-x)))
}

func (net *ThreatNet) sigmoidPrime(x float64) float64 {
	return ((x) * (1 - x))
}

// forward performs the feed-forwarding of the layer weights
// with the neurons of the previous layer to give the succeeding
// hidden layer and returns single output neuron.
func (net *ThreatNet) forward(input VectorFloat) float64 {
	// Start with the input layer.
	currentLayer := VectorFloat(input)

	// For each weight layer in the weight list.
	for _, weight := range net.weights {
		// Number of neurons in the next layer (hidden till output)
		// will be equal to the weights per neuron of the previous layer.
		nextLayer := make(VectorFloat, len(weight[0]))

		// for each weight corresponding to the neuron in the previous iteration.
		for j := 0; j < len(weight[0]); j++ {
			sum := 0.0
			// for each neuron in the current layer.
			for i := 0; i < len(currentLayer); i++ {
				sum += currentLayer[i] * weight[i][j]
			}
			nextLayer[j] = net.sigmoid(sum)
		}

		// Update the current layer to be the next layer.
		currentLayer = nextLayer
	}

	// Return the single output neuron.
	return currentLayer[0]
}

// forwardFull is extended version of forward which returns the
// values of the neurons of all the layers for backpropogation.
func (net *ThreatNet) forwardFull(input VectorFloat) Matrix {
	// Initialize all layers holder.
	allLayers := make(Matrix, len(net.topology))
	allLayers[0] = input // First layer is the input layer.

	currentLayer := VectorFloat(input)

	for l, weight := range net.weights {
		nextLayer := make(VectorFloat, len(weight[0]))
		for j := 0; j < len(weight[0]); j++ {
			sum := 0.0
			for i := 0; i < len(currentLayer); i++ {
				sum += currentLayer[i] * weight[i][j]
			}
			nextLayer[j] = net.sigmoid(sum)
		}

		// Keep appending the layers.
		allLayers[l+1] = nextLayer

		// Update the current layer to be the next layer.
		currentLayer = nextLayer
	}

	return allLayers
}

// train performs the feed-forwarding of the input using
// forwardFull (storing the hidden layers, as well) and
// backpropogating error.
func (net *ThreatNet) train(input VectorFloat, target float64) {
	// Step 1: forward pass, store all layer outputs
	allLayers := net.forwardFull(input)
	last := len(allLayers) - 1

	// Step 2: output layer error and delta
	outputError := target - allLayers[last][0]
	outputDelta := outputError * net.sigmoidPrime(allLayers[last][0])

	// Step 3: update output layer weights (weights[last-1])
	for i := 0; i < len(allLayers[last-1]); i++ {
		net.weights[last-1][i][0] += allLayers[last-1][i] * outputDelta
	}

	// Step 4: propagate backwards through hidden layers
	// currentDeltas starts as slice containing just outputDelta
	currentDeltas := VectorFloat{outputDelta}

	for l := last - 1; l >= 1; l-- {
		nextDeltas := make(VectorFloat, len(allLayers[l]))

		for i := 0; i < len(allLayers[l]); i++ {
			// Sum up error from all neurons in the next layer
			errSum := 0.0
			for j := 0; j < len(currentDeltas); j++ {
				errSum += currentDeltas[j] * net.weights[l][i][j]
			}
			nextDeltas[i] = errSum * net.sigmoidPrime(allLayers[l][i])

			// Update weights for this layer
			for j := 0; j < len(allLayers[l-1]); j++ {
				net.weights[l-1][j][i] += allLayers[l-1][j] * nextDeltas[i]
			}
		}

		currentDeltas = nextDeltas
	}
}

// SaveWeights processes and saves the Neural Net configuration (weights)
// to disk for re-use.
func (net *ThreatNet) SaveWeights(path string) error {
	data, err := json.Marshal(net.weights)
	if err != nil {
		return err
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

// LoadWeights loads the weights from the disk to memory for
// easy and quick start-up of the application.
func (net *ThreatNet) LoadWeights(path string) error {
	var weights Layer

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &weights)
	if err != nil {
		return err
	}

	net.weights = weights

	return nil
}

// toFloat64 is a helper function to convert any type to float64
// for normalization. Defaults to returning 0.0
func toFloat64(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case uint16:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case bool:
		{
			if v {
				return 1.0
			}
			return 0.0
		}
	default:
		return 0.0
	}
}

// normalize scales the input value to a range between 0.0 and 1.0
// based on the provided lower and upper bounds (Min-Max normalization).
func normalize(value, min, max float64) float64 {
	return ((value - min) / (max - min))
}

// packetToInputVector converts a 'Packet' instance (input)
// to a slice of 10 float64 value for passing in as input
// to the ThreatNet classifier.
func packetToInputVector(p *Packet) []float64 {
	finalVector := make([]float64, 10)

	finalVector[0] = toFloat64(p.Flags.SYN)
	finalVector[1] = toFloat64(p.Flags.ACK)
	finalVector[2] = toFloat64(p.Flags.FIN)
	finalVector[3] = toFloat64(p.Flags.RST)
	finalVector[4] = toFloat64(p.Flags.PSH)
	finalVector[5] = toFloat64(p.Flags.URG)
	finalVector[6] = normalize(toFloat64(p.SrcPort), 1, 65536)     // uint16 (max value)
	finalVector[7] = normalize(toFloat64(p.DestPort), 1, 65536)    // uint16 (max value)
	finalVector[8] = normalize(toFloat64(p.Size), 0, 65536)        // maximum IP packet size.
	finalVector[9] = normalize(toFloat64(p.PacketRate), 0, 1000.0) // Reasonable upper bound, before something is deviating.

	return finalVector
}
