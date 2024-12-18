import streamlit as st
from utils import *
from fuzzywuzzy import fuzz
import sqlite3

def country():
    col1, col2, col3 = st.columns((0.4, 0.40, 0.2))

    with col1:
        first_name = st.text_input('First Name', value='Jila')
        middle_name = st.text_input('Middle Name', value='Fakour')
        sur_name = st.text_input('Last Name', value='Tahmasebi')
        dob = st.text_input('DOB', value='7/5/1958')
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
                resident_df = pd.read_csv("Australia source 1.csv", usecols=usecols)
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
                                        'Postcode':'POSTCODE'})
                # st.write(df)
                # usecols = ['First_Name','Gn_1_2','Sur_Name','DOB_Formatted','Ad1','Suburb','State','Postcode','Phone2_Mobile','EmailAddress']

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
                    df['Match Level'] = 'Transposed Match'
                
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

                # st.write("source",source)
                # st.write("parsed_address",parsed_address)
                # st.write("address_str",address_str)
                df_transposed = df.T
                df_transposed.columns = ['Results']
                st.dataframe(df_transposed, width=550, height=900)    
                
                    
                # except snowflake.connector.errors.ProgrammingError as e:
                #     st.error(f"Error executing query: {e}")
            

            


if __name__ == '__main__':
    country()