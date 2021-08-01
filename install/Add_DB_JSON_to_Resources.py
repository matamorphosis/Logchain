import os, sys, json

try:

    with open('db.json') as JSON_File:
        Configuration_Data = json.load(JSON_File)
        JSON_File.close()

    Lib_Location = "../lib/config"

    for item in os.listdir(Lib_Location):

        if item in ['agent', 'ledger']:
            Combined_Path = os.path.join(Lib_Location, item)

            if os.path.isdir(Combined_Path):
                Config_File = os.path.join(Combined_Path, "config.json")

                with open(Config_File) as Config_JSON_File:
                    Configuration_File_Data = json.load(Config_JSON_File)
                    Config_JSON_File.close()

                Configuration_File_Data['postgresql'] = Configuration_Data['postgresql']
                Configuration_File_Data_JSON = json.dumps(Configuration_File_Data, indent=4, sort_keys=True)
                File_Output = open(Config_File, "w")
                File_Output.write(Configuration_File_Data_JSON)
                File_Output.close()

except Exception as e:
    sys.exit(f"[-] {str(e)}.")