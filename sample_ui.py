import streamlit as st
from utils import *
from fuzzywuzzy import fuzz
import sqlite3
from cryptography.fernet import Fernet
import pandas as pd
import base64
from dotenv import load_dotenv
import os
import io

st.set_page_config(page_title="KYC Verification", layout="wide")
st.markdown("<h1 style='text-align: center; color: blue;'>KYC Verification System</h1>", unsafe_allow_html=True)

selected_country = st.radio(
    ':green[**Country Selection :**]',
    ['Australia', 'Mexico'],
    horizontal=True)

def au_country():
    col1, col2, col3 = st.columns((0.45, 0.55, 0.45))

    with col1:
        first_name = st.text_input('First Name', value='Jila')
        middle_name = st.text_input('Middle Name', value='Fakour')
        sur_name = st.text_input('Last Name', value='Tahmasebi')
        dob = st.text_input('DOB', value='1958-07-05')
        col11,col12,col13,col14=st.columns((4))
        with col11:
            address_line1 = st.text_input('Address Line 1', value="4 Melissa St")
        with col12:
            suburb = st.text_input('Suburb', value="DUNCRAIG")
        with col13:
            state = st.text_input('State', value="WA")
        with col14:
            postcode = st.text_input('Postcode', value="6023")
        mobile = st.text_input('Mobile', value='421074419')
        email = st.text_input('Email Address', value='jila_fakour@yahoo.co.uk')

        if st.button('Search'):

            with col2:
                usecols = ['First_Name','Gn_1_2','Sur_Name','DOB_Formatted','Ad1','Suburb','State','Postcode','Phone2_Mobile','EmailAddress']
                # resident_df = pd.read_csv("Australia source 1.csv", usecols=usecols)
                def generate_key(password):
                    from hashlib import sha256
                    return Fernet(base64.urlsafe_b64encode(sha256(password.encode()).digest()))
                
                load_dotenv()
                password = os.getenv("PASSWORDKYC")
                cipher = generate_key(password)

                with open("Australia source 1 encripted.pkl", "rb") as f:
                    encrypted_data = f.read()

                decrypted_data = cipher.decrypt(encrypted_data)

                # Use io.BytesIO to load the decrypted data into a DataFrame
                decrypted_file = io.BytesIO(decrypted_data)
                df = pd.read_pickle(decrypted_file)
                
                # Extract specific columns
                resident_df = df[usecols]
                conn = sqlite3.connect(':memory:')

                # Load the DataFrame into the SQLite database
                resident_df.to_sql('AU_RESIDENTIAL', conn, index=False, if_exists='replace')
                query = f"""
                    WITH InputData AS (
                        SELECT
                            '{first_name}' AS first_name_input,
                            '{middle_name}' AS middle_name_input,
                            '{sur_name}' AS sur_name_input,
                            '{dob}' AS dob_input
                    )
                    SELECT
                        First_Name, Gn_1_2,Sur_Name,DOB_Formatted,Ad1,Suburb,State,Postcode,Phone2_Mobile,EmailAddress
                    FROM
                        AU_RESIDENTIAL AS resident,
                        InputData AS input
                     WHERE
                         (
                             -- Exact case-insensitive matches, but only if the input is not empty or NULL
                             (LOWER(input.sur_name_input) IS NOT NULL AND LOWER(input.sur_name_input) != '' AND LOWER(resident.sur_name) like LOWER(input.sur_name_input))\
                             OR (LOWER(input.middle_name_input) IS NOT NULL AND LOWER(input.middle_name_input) != '' AND LOWER(resident.Gn_1_2) = LOWER(input.middle_name_input))\
                             OR (LOWER(input.first_name_input) IS NOT NULL AND LOWER(input.first_name_input) != '' AND LOWER(resident.first_name) = LOWER(input.first_name_input))\
                             AND (input.dob_input IS NOT NULL AND input.dob_input != '' AND resident.DOB_Formatted = input.dob_input)                         )
                    LIMIT 1
                 """
                # df = pd.read_sql_query(query, conn)
                # try:
                df = pd.read_sql_query(query, conn)
                df = df.rename(columns={'First_Name':'FIRST_NAME','Gn_1_2':'MIDDLE_NAME','Sur_Name':'SUR_NAME',\
                                        'DOB_Formatted':'DOB','Ad1':'AD1','Suburb':"SUBURB",'State':'STATE',\
                                        'Postcode':'POSTCODE', 'EmailAddress':'EMAILADDRESS'})
                df['DOB'] = pd.to_datetime(df['DOB'])
                df['DOB'] = df['DOB'].dt.date

                fields = [
                ('FIRST_NAME', first_name, 0),
                ('MIDDLE_NAME', middle_name, 1),
                ('SUR_NAME', sur_name, 2)
                    ]
                def update_name_str(row):
                    name_Str = "XXX" 
                    for db_column, input_field, str_index in fields:
                        name_Str = apply_name_matching(row, name_Str, db_column, input_field, str_index)
                    return name_Str
                df['Name Match Str'] = df.apply(update_name_str, axis=1)
                df['first_name_similarity'] = df['FIRST_NAME'].apply(lambda x: textdistance.jaro_winkler(x.lower(), first_name.lower()) * 100).apply(lambda score: int(score) if score > 65 else 0) 
                df['middle_name_similarity'] = df['MIDDLE_NAME'].apply(lambda x: textdistance.jaro_winkler(x.lower(), middle_name.lower())*100).apply(lambda score: int(score) if score > 65 else 0) 
                df['sur_name_similarity'] = df['SUR_NAME'].apply(lambda x: textdistance.jaro_winkler(x.lower(), sur_name.lower())*100).apply(lambda score: score if int(score) > 65 else 0) 

                if df['Name Match Str'][0][0] == 'T':
                    df['first_name_similarity'] = 100
                if df['Name Match Str'][0][1] == 'T':
                    df['middle_name_similarity'] = 100
                if df['Name Match Str'][0][2] == 'T':
                    df['sur_name_similarity'] = 100

                full_name_request = (first_name.strip() + " " + middle_name.strip() + " "+ sur_name.strip()).strip().lower()
                full_name_matched = (df['FIRST_NAME'][0].strip()+ " "+df['MIDDLE_NAME'][0].strip()+ " "+df['SUR_NAME'][0].strip()).lower()
                name_obj = Name(full_name_request)
                # st.write(name_obj)
                
                # Apply the different matching methods from the Name class
                match_results = {
                    "Exact Match": (df['Name Match Str'] == 'EEE').any(),
                    "Hyphenated Match": name_obj.hyphenated(full_name_matched),
                    "Transposed Match": name_obj.transposed(full_name_matched),
                    "Middle Name Mismatch": df['Name Match Str'].str.contains('E.*E$', regex=True).any(),
                    "Initial Match": name_obj.initial(full_name_matched),
                    "SurName only Match": df['Name Match Str'].str.contains('^[ETMD].*E$', regex=True).any(),
                    "Fuzzy Match": name_obj.fuzzy(full_name_matched),
                    "Nickname Match": name_obj.nickname(full_name_matched),
                    "Missing Part Match": name_obj.missing(full_name_matched),
                    "Different Name": name_obj.different(full_name_matched)
                }
                
                # Filter out any matches that returned False
                match_results = {k: v for k, v in match_results.items() if v}
                top_match = next(iter(match_results.items()), ("No Match Found", ""))

                df['Name Match Level'] = top_match[0]
                
                df['full_name_similarity'] = (textdistance.jaro_winkler(full_name_request,full_name_matched)*100) 
                df['full_name_similarity'] = df['full_name_similarity'].apply(lambda score: int(score) if score > 65 else 0)
                if fuzz.token_sort_ratio(full_name_request,full_name_matched)==100 and top_match[0] !='Exact Match':
                    df['full_name_similarity'] = 100
                    # df['Match Level'] = 'Transposed Match'
                
                df['dob_match'] = df['DOB'].apply(lambda x: Dob(dob).exact(x))
                address_str = "XXXXXX"

                source = {
                    # 'Gnaf_Pid': address_id,
                    'Ad1': df["AD1"][0],
                    'Suburb': df["SUBURB"][0],
                    'State': df["STATE"][0],
                    'Postcode': str(df["POSTCODE"][0])
                }
                source_output = address_parsing(df['AD1'][0])
                source = {**source, **source_output}
                # st.write(source)


                parsed_address = {
                    # 'Gnaf_Pid': address_id,
                    'Ad1': address_line1,
                    'Suburb': suburb,
                    'State': state,
                    'Postcode': str(postcode)
                }
                parsed_output = address_parsing(address_line1)
                parsed_address = {**parsed_address, **parsed_output}
                # st.write(parsed_address)

                address_checker = Address(parsed_address=parsed_address,source_address=source)
                address_str=address_checker.address_line1_match(address_str)
                df['Address Matching String'] = address_str

                df['address_line_similarity'] = df['AD1'].apply(lambda x: textdistance.jaro_winkler(x.lower(), address_line1.lower()) * 100).apply(lambda score: int(score) if score > 65 else 0) 
                weight1 = 40 if 90<=df['address_line_similarity'][0] <=100 else 30 if 85<=df['address_line_similarity'][0] <90 else 0 
                
                df['suburb_similarity'] = df['SUBURB'].apply(lambda x: textdistance.jaro_winkler(x.lower(), suburb.lower()) * 100).apply(lambda score: int(score) if score > 65 else 0) 
                weight2 = 30 if 90<=df['suburb_similarity'][0] <=100 else 25 if 85<=df['suburb_similarity'][0] <90 else 0 
                
                df['state_similarity'] = df['STATE'].apply(lambda x: textdistance.jaro_winkler(x.lower(), state.lower()) * 100).apply(lambda score: int(score) if score > 65 else 0) 
                weight3 = 10 if 90<=df['state_similarity'][0] <=100 else  0

                df['postcde_similarity'] = df['POSTCODE'].astype(str).apply(lambda x: 100 if x == postcode else 0) 
                weight4 = 20 if df['postcde_similarity'][0] ==100 else 0 
                
                total_weight = weight1+weight2+weight3+weight4
                if total_weight > 90:
                    match_level = f'Full Match, {total_weight}'
                elif 80 <= total_weight <= 90:
                    match_level = f'Partial Match, {total_weight}'
                else:
                    match_level = 'No Match'
                df['Address Match Level'] = match_level

                matching_levels = get_matching_level(df,dob,mobile,email,df['full_name_similarity'][0],total_weight)
                df['Overall Matching Level'] = ', '.join(matching_levels)
                df["Overall Verified Level"] = append_based_on_verification(df,verified_by=True)
                df_transposed = df.T
                df_transposed.columns = ['Results']
                index_col = ['Name Match Str','Name Match Level','dob_match','Address Matching String',
                                                'Address Match Level','Overall Matching Level','Overall Verified Level']
                with st.expander(":red[**Summary Data:**]"):
                    st.dataframe(df_transposed.loc[index_col], width=550, height=300)   
                with st.expander(":red[**Detailed Data:**]"):
                    st.dataframe(df_transposed.drop(index_col), width=550, height=650)    
            
            with col3:
                display_match_explanation()
                

def mx_country():
    col1, col2, col3 = st.columns((0.35, 0.3, 0.5))

    with col1:
        first_name = st.text_input('First Name', value='MARIA EUGENIA')
        # middle_name = st.text_input('Middle Name', value='Fakour')
        sur_name = st.text_input('Last Name', value='HERNANDEZ SEGOVIA')
        dob = st.text_input('DOB', value='2002-12-22')
        address_line1 = st.text_input('Address', value='  Monterrey Nuevo León 64930.0')

        mobile = st.text_input('Mobile', value='528117833124')
        email = st.text_input('Email Address', value='')

        if st.button('Search'):
            with col2:
                usecols = ['CURP',	"FirstName"	, "LastName",	"DOB",	"address",	"EmailAddress",	"Phone"]
                # resident_df = pd.read_excel("Mexico Sample 100k v1 20240717.xlsx", usecols=usecols)
                def generate_key(password):
                    from hashlib import sha256
                    return Fernet(base64.urlsafe_b64encode(sha256(password.encode()).digest()))
                
                load_dotenv()
                password = os.getenv("PASSWORDKYC")
                cipher = generate_key(password)

                with open("Mexico Sample 100k v1 20240717.pkl encrypted.pkl", "rb") as f:
                    encrypted_data = f.read()

                decrypted_data = cipher.decrypt(encrypted_data)

                # Use io.BytesIO to load the decrypted data into a DataFrame
                decrypted_file = io.BytesIO(decrypted_data)
                df = pd.read_pickle(decrypted_file)
                
                # Extract specific columns
                resident_df = df[usecols]

                conn = sqlite3.connect(':memory:')

                # Load the DataFrame into the SQLite database
                resident_df.to_sql('MX_RESIDENTIAL', conn, index=False, if_exists='replace')
                query = f"""
                    WITH InputData AS (
                        SELECT
                            '{first_name}' AS first_name_input,
                            '{sur_name}' AS sur_name_input,
                            '{dob}' AS dob_input
                    )
                    SELECT
                        CURP,	FirstName, LastName,	DOB, address,	EmailAddress,	Phone
                    FROM
                        MX_RESIDENTIAL AS resident,
                        InputData AS input
                     WHERE
                         (
                             -- Exact case-insensitive matches, but only if the input is not empty or NULL
                             (LOWER(input.sur_name_input) IS NOT NULL AND LOWER(input.sur_name_input) != '' AND LOWER(resident.LastName) like LOWER(input.sur_name_input))\
                             OR (LOWER(input.first_name_input) IS NOT NULL AND LOWER(input.first_name_input) != '' AND LOWER(resident.FirstName) = LOWER(input.first_name_input))\
                             AND (input.dob_input IS NOT NULL AND input.dob_input != '' AND resident.DOB = input.dob_input)                         )
                    LIMIT 1
                 """
                # df = pd.read_sql_query(query, conn)
                # try:
                df = pd.read_sql_query(query, conn)
                df = df.rename(columns={'FirstName':'FIRST_NAME','LastName':'SUR_NAME',\
                                        'DOB':'DOB','address':'AD1',\
                                        "EmailAddress":'EMAILADDRESS','Phone':'Phone2_Mobile'})
                df['DOB'] = pd.to_datetime(df['DOB'])
                df['DOB'] = df['DOB'].dt.date
                fields = [
                ('FIRST_NAME', first_name, 0),
                ('SUR_NAME', sur_name, 1)
                    ]
                def update_name_str(row):
                    name_Str = "XX" 
                    for db_column, input_field, str_index in fields:
                        name_Str = apply_name_matching(row, name_Str, db_column, input_field, str_index)
                    return name_Str
                df['Name Match Str'] = df.apply(update_name_str, axis=1)        
            
                df['first_name_similarity'] = df['FIRST_NAME'].apply(lambda x: textdistance.jaro_winkler(x.lower(), first_name.lower()) * 100).apply(lambda score: int(score) if score > 65 else 0) 
                df['sur_name_similarity'] = df['SUR_NAME'].apply(lambda x: textdistance.jaro_winkler(x.lower(), sur_name.lower())*100).apply(lambda score: score if int(score) > 65 else 0) 

                if df['Name Match Str'][0][0] == 'T':
                    df['first_name_similarity'] = 100
                if df['Name Match Str'][0][1] == 'T':
                    df['sur_name_similarity'] = 100

                full_name_request = (first_name.strip() + " " + sur_name.strip()).strip().lower()
                full_name_matched = (df['FIRST_NAME'][0].strip()+ " "+df['SUR_NAME'][0].strip()).lower()
                name_obj = Name(full_name_request)
                # st.write(name_obj)
                
                # Apply the different matching methods from the Name class
                match_results = {
                    "Exact Match": (df['Name Match Str'] == 'EE').any(),
                    "Hyphenated Match": name_obj.hyphenated(full_name_matched),
                    "Transposed Match": name_obj.transposed(full_name_matched),
                    "Middle Name Mismatch": df['Name Match Str'].str.contains('E.*E$', regex=True).any(),
                    "Initial Match": name_obj.initial(full_name_matched),
                    "SurName only Match": df['Name Match Str'].str.contains('^[ETMD].*E$', regex=True).any(),
                    "Fuzzy Match": name_obj.fuzzy(full_name_matched),
                    "Nickname Match": name_obj.nickname(full_name_matched),
                    "Missing Part Match": name_obj.missing(full_name_matched),
                    "Different Name": name_obj.different(full_name_matched)
                }
                
                # Filter out any matches that returned False
                match_results = {k: v for k, v in match_results.items() if v}
                top_match = next(iter(match_results.items()), ("No Match Found", ""))

                df['Name Match Level'] = top_match[0]
                
                df['full_name_similarity'] = (textdistance.jaro_winkler(full_name_request,full_name_matched)*100) 
                df['full_name_similarity'] = df['full_name_similarity'].apply(lambda score: int(score) if score > 65 else 0)
                if fuzz.token_sort_ratio(full_name_request,full_name_matched)==100 and top_match[0] !='Exact Match':
                    df['full_name_similarity'] = 100
                    # df['Match Level'] = 'Transposed Match'
                
                df['dob_match'] = df['DOB'].apply(lambda x: Dob(dob).exact(x))
                address_str = "XXXXXX"

                # source = {
                #     # 'Gnaf_Pid': address_id,
                #     'Ad1': df["AD1"][0],
                #     'Suburb': df["SUBURB"][0],
                #     'State': df["STATE"][0],
                #     'Postcode': str(df["POSTCODE"][0])
                # }
                # source_output = address_parsing(df['AD1'][0])
                # source = {**source, **source_output}
                # # st.write(source)


                # parsed_address = {
                #     # 'Gnaf_Pid': address_id,
                #     'Ad1': address_line1,
                #     'Suburb': suburb,
                #     'State': state,
                #     'Postcode': str(postcode)
                # }
                # parsed_output = address_parsing(address_line1)
                # parsed_address = {**parsed_address, **parsed_output}
                # # st.write(parsed_address)

                # address_checker = Address(parsed_address=parsed_address,source_address=source)
                # address_str=address_checker.address_line1_match(address_str)
                # df['Address Matching String'] = address_str

                df['address_similarity'] = df['AD1'].apply(lambda x: textdistance.jaro_winkler(x.lower(), address_line1.lower()) * 100).apply(lambda score: int(score) if score > 65 else 0) 
                weight1 = df['address_similarity'][0] 
                
                # df['suburb_similarity'] = df['SUBURB'].apply(lambda x: textdistance.jaro_winkler(x.lower(), suburb.lower()) * 100).apply(lambda score: int(score) if score > 65 else 0) 
                # weight2 = 30 if 90<=df['suburb_similarity'][0] <=100 else 25 if 85<=df['suburb_similarity'][0] <90 else 0 
                
                # df['state_similarity'] = df['STATE'].apply(lambda x: textdistance.jaro_winkler(x.lower(), state.lower()) * 100).apply(lambda score: int(score) if score > 65 else 0) 
                # weight3 = 10 if 90<=df['state_similarity'][0] <=100 else  0

                # df['postcde_similarity'] = df['POSTCODE'].astype(str).apply(lambda x: 100 if x == postcode else 0) 
                # weight4 = 20 if df['postcde_similarity'][0] ==100 else 0 
                
                total_weight = weight1
                if total_weight > 90:
                    match_level = f'Full Match, {total_weight}'
                elif 80 <= total_weight <= 90:
                    match_level = f'Partial Match, {total_weight}'
                else:
                    match_level = 'No Match'
                df['Address Match Level'] = match_level

                # st.write(df['EmailAddress'][0])
                matching_levels = get_matching_level(df,dob,mobile,email,df['full_name_similarity'][0],total_weight)
                df['Overall Matching Level'] = ', '.join(matching_levels)
                df["Overall Verified Level"] = append_based_on_verification(df,verified_by=True)
                df_transposed = df.T
                df_transposed.columns = ['Results']
                # st.dataframe(df_transposed, width=550, height=650)  
                index_col = ['Name Match Str','Name Match Level','dob_match',
                                                'Address Match Level','Overall Matching Level','Overall Verified Level']
                with st.expander(":red[**Summary Data:**]"):
                    st.dataframe(df_transposed.loc[index_col], width=550, height=250)   
                with st.expander(":red[**Detailed Data:**]"):
                    st.dataframe(df_transposed.drop(index_col), width=550, height=420)    
            
            with col3:
                display_match_explanation()  

if __name__ == '__main__':
    if selected_country == 'Australia':
        au_country()
    if selected_country == 'Mexico':
        mx_country()