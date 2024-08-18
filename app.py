# -*- coding: utf-8 -*-
"""
Created

For the deployment of the IOMT traffic classification model
"""

import numpy as np
import pickle
import gzip
import streamlit as st
from PIL import Image


# Decompress and load the model
model_file = r"compressed_iomt_traffic_attack_detector.pkl.gz"
with open(model_file, 'rb') as zip_file:
    loaded_model = pickle.load(zip_file)


# Classification function
def classifier_func(input_data):
    
    # Convert input_data to numpy array
    input_data_as_array = np.array(input_data).reshape(1, -1)

    # Predict with model
    prediction = loaded_model.predict(input_data_as_array)
    
    # Map prediction to intelligible categories
    attack_mapping = {
        1: 'Cyber-Attack: ARP Spoofing ❌',
        2: 'Cyber-Attack: DDoS ❌',
        3: 'Cyber-Attack: DoS ❌',
        4: 'Cyber-Attack: MQTT Attack ❌',
        5: 'Cyber-Attack: Recon ❌'
    }
    
    return attack_mapping.get(prediction[0], 'Traffic is benign ✅')


# Streamlit code
def main():
    
    # Set the title and page icon
    st.set_page_config(
        page_title="Detection of IoMT Cyberattacks",
        page_icon="🏥"
    )
    
    
    # Custom theme
    custom_css = """
    <style>
        body {
            color: #1E1E1E;
            background-color: #E6E6FA;  /* Lilac background color */
        }
        .sidebar .sidebar-content {
            background-color: #9370DB;  /* Medium purple for the sidebar */
            color: #FFFFFF;
        }
        .st-bq {
            color: #8A2BE2;  /* Blue violet text color */
        }
        .st-cg {
            color: #28a745;
        }
        .st-dn {
            color: #28a745;
        }
        .st-eu {
            background-color: #28a745;
        }
        .stAlert {
            color: green;  /* Green text color for st.success */
        }
    </style>
    """

    # Apply the custom theme
    st.markdown(custom_css, unsafe_allow_html=True)
        
        
    # Navigation
    page_options = ["Homepage", "Detection"]
    app_mode = st.sidebar.selectbox('Select Page', page_options) 
    
    if app_mode=='Homepage':
        homepage_func()
        
    elif app_mode == 'Detection':
        detection_page_func()
        

def homepage_func():
    # Homepage Information
    st.title('Detection of Cyberattacks in IOMT networks')
    st.markdown(
        'Detecting cyberattacks in the networks of the Internet of Medical Things (IoMT) is crucial, '
        'given the sensitivity of healthcare data and the potential impacts of cyberattacks on medical networks. '
        'This web application is created for educational purposes to demonstrate the detection of cyberattacks in IoMT networks.'
    )

    image_file = r"iomt_img.jpg"
    image = Image.open(image_file)
    st.image(image)
        
    st.markdown('Welcome to the IoMT Cyberattacks Detection Application.')
    st.markdown('Use the sidebar to navigate to the _Detection_ page.')
    
    
def detection_page_func(): 
    st.title('IOMT Traffic Classification')
    st.header('Customize Parameters for Cyberattack Detection in IOMT networks')
    st.divider()
        
    # Input controls to get data from the user
    col1, col2, col3 = st.columns(3)
    
    with col1:
        IAT = st.number_input('Inter-Arrival Time between Packets')
        header_length = st.number_input('Header Length')
        total_size = st.number_input('Total Size of Packets')
        avg = st.number_input('Average')
        rate = st.number_input('Flow Rate')

    with col2:
        ack_flag_number = st.number_input('ACK Flag Number')
        fin_flag_number = st.number_input('FIN Flag Number')
        psh_flag_number = st.number_input('PSH Flag Number')
        rst_flag_number = st.number_input('RST Flag Number')
        syn_flag_number = st.number_input('SYN Flag Number')
        
    with col3:
        mgtd = st.number_input('Magnitude')
        ack_count = st.number_input('ACK Count')
        fin_count = st.number_input('FIN Count')
        rst_count = st.number_input('RST Count')
        maxm = st.number_input('Maximum')
        
    
    # List of user inputs
    input_list = [IAT, rst_count, header_length, fin_count, avg,
                  total_size, rate, ack_count, mgtd, ack_flag_number, 
                  maxm, fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number]
        
    # Detection result
    result = ''
                
    if st.button('Detect'):
         result = classifier_func(input_list)
         
    st.success(result)

    
if __name__ == '__main__':
    main()

    
