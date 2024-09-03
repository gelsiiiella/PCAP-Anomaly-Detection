import asyncio
import pyshark
import numpy as np
from flask import Flask, render_template, request, jsonify
from scipy.stats import norm
import concurrent.futures
import queue

app = Flask(__name__)

# Baseline Data for statistical calculations(mean, and standard deviation)
baseline_packet_lengths = [64, 128, 256, 512, 1024,2048, 4096, 8192, 16384]

# Calculation of baseline statistics
baseline_mean = np.mean(baseline_packet_lengths)
baseline_std = np.std(baseline_packet_lengths)

# Calculate the probability based on z-score
def calculate_probability(x, baseline_mean, baseline_std):
    z_score = (x - baseline_mean) / baseline_std
    probability = norm.cdf(z_score)
    # Debug print statement for tracing
    print(f"Length: {x}, Z-Score: {z_score:.2f}, Probability: {probability:.4f}")
    return probability

# Risk assessment based on the probability. 
# This where cumulative distribution compare calculated probability of an observation 
# against predefined thresholds to detrmine the level of risk or likelihood of anomaly.
def assess_risk(probability):
    if probability < 0.01:
        return "High Risk"
    elif probability < 0.05:
        return "Medium Risk"
    elif probability < 0.1:
        return "Low Risk"
    else:
        return "No Risk"
    
#Pyshark Get PCAP Protocol 
def get_protocol(packet):
    protocol_map = {
        '1': 'ICMP',
        '6': 'TCP',
        '17': 'UDP'
    }
    if hasattr(packet, 'ip'):
        return protocol_map.get(packet.ip.proto, f"Unknown ({packet.ip.proto})")
    return packet.highest_layer

    
# Analyze pcap file and detect anomalies
def analyze_pcap(file_path, result_queue, baseline_mean, baseline_std):
    # Create a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    capture = pyshark.FileCapture(file_path)
    results = []
    
    try:
        
        for i, packet in enumerate(capture, start=1):
            # Debug print to confirm packet processing
            print(f"Processing packet {i}")
            packet_length = int(packet.length)
            probability = calculate_probability(packet_length, baseline_mean, baseline_std)
            risk = assess_risk(probability)
            protocol = get_protocol(packet)
            # Debug print statement for tracing packet details
            print(f"Packet {i}: Length: {packet_length}, Probability: {probability:.4f}, Risk: {risk}, Protocol: {protocol}")
            # Append all packet details
            results.append({
                'packet_number': i,
                'length': packet_length,
                'probability': probability,
                'risk': risk,
                'protocol': protocol,
            })

    except AttributeError as e:
        print(f"Error processing packet: {e}")
    
    result_queue.put(results)
    
    # Close the event loop
    loop.close()

# Route to display the frontend
@app.route('/')
def home():
    return render_template('index.html')

# Route to handle file upload and analysis
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file_path = f"./uploads/{file.filename}"
    file.save(file_path)
    
    result_queue = queue.Queue()
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit the analysis task to the thread pool
        future = executor.submit(analyze_pcap, file_path, result_queue, baseline_mean, baseline_std)
        future.result()
    
    # Retrieve the analysis results
    results = result_queue.get()
    
    # Return the detailed analysis results
    return jsonify({"results": results})

if __name__ == '__main__':
    app.run(debug=True)
