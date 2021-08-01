#!/usr/bin/bash

function install_dependencies() {
    printf "\xE2\x9C\x94 Installing dependencies."
    if [ -f /etc/redhat-release ]; then
	    yum update
      yum install -y yum-utils python36-setuptools python3-psycopg2
      easy_install-3.6 pip
    fi

    if [ -f /etc/lsb-release ]; then
      apt update
      apt install -y python3 python3-pip python3-psycopg2 build-essential
    fi

    if [ -e /etc/os-release ]; then
      . /etc/os-release
    else
      . /usr/lib/os-release
    fi

    if [[ "$ID_LIKE" = *"suse"* ]]; then
      zypper update
      zypper install -n python3 python3-pip python3-psycopg2
      zypper install -n -t pattern devel_basis
    fi

    pip3 install -r requirements.txt &
    printf "\xE2\x9C\x94 Installation complete.\n"
}

function install_database() {
    printf "\xE2\x9C\x94 Installing database dependencies.\n"
    service
    whichpsql=`which psql`

    if [ "$whichpsql" == "" ]; then
        if [ -f /etc/redhat-release ]; then
          yum update
          yum install -y postgresql postgresql-contrib
        fi

        if [ -f /etc/lsb-release ]; then
          apt update
          apt install -y postgresql postgresql-contrib
        fi

        if [ -e /etc/os-release ]; then
          . /etc/os-release
        else
          . /usr/lib/os-release
        fi

        if [[ "$ID_LIKE" = *"suse"* ]]; then
          zypper update
          zypper install -n postgresql postgresql-contrib
        fi
    else
        psqlstatus=`systemctl is-active postgresql.service`
        if [ "$psqlstatus" == "inactive" ]; then
          service postgresql start
        fi
    fi

    printf "\xE2\x9C\x94 Installation complete."
    DATABASE="logchain"
    USER="logchain"
    PASSWD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`
    sudo -u postgres psql -c "CREATE DATABASE $DATABASE;"
    sudo -u postgres psql -c "CREATE USER $USER WITH ENCRYPTED PASSWORD '$PASSWD';"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DATABASE TO $USER;"
    echo "{" > db.json
    echo "    \"postgresql\": {" >> db.json
    echo "        \"host\": \"127.0.0.1\"," >> db.json
    echo "        \"port\": 5432," >> db.json
    echo "        \"database\": \"$DATABASE\"," >> db.json
    echo "        \"user\": \"$USER\"," >> db.json
    echo "        \"password\": \"$PASSWD\"" >> db.json
    echo "    }" >> db.json
    echo "}" >> db.json
    python3 Add_DB_JSON_to_Resources.py
    printf "\xE2\x9C\x94 Database Details:\n"
    echo $DATABASE
    echo $USER
    echo $PASSWD
    printf "\xE2\x9C\x94 Database setup complete.\n"
    python3 Create_Tables.py
    printf "\xE2\x9C\x94 Logchain tables created.\n"
}

PS3='Please select what you would like to install: '
options=("Agent" "Ledger" "PostgreSQL Database" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Agent")
            install_dependencies
            locations=()
            read -p "Please enter the location of your logs, if you have multiple you will need to enter them one by one: " location
            locations+=("$location")

            more_locations () {
              read -p "Please enter the location of your logs: " additional_location
              locations=("${locations[@]} $additional_location")
            }

            while true; do
                read -p "Do you wish to add another location? " yn
                case $yn in
                    [Yy]* ) more_locations;;
                    [Nn]* ) break;;
                    * ) echo "Please answer yes or no.";;
                esac
            done

            read -p "Please enter the direcory where you wish to store the backups. " target_directory

            JSON_Locations=`python3 -c 'import json, sys; print(json.dumps([v for v in sys.argv[1:]]))' $locations`
            if [ ! -d ../lib/config ]; then
                mkdir ../lib/config
            fi
            mkdir ../lib/config/agent

            Agent_Config_File="../lib/config/agent/config.json"
            echo "{" > $Agent_Config_File
            echo "    \"agent\": {" >> $Agent_Config_File
            echo "        \"source_log_directories\": $JSON_Locations," >> $Agent_Config_File
            echo "        \"target_backup_directory\": \"$target_directory\"" >> $Agent_Config_File
            echo "    }," >> $Agent_Config_File
            echo "    \"api\": {" >> $Agent_Config_File
            echo "        \"host\": \"http://127.0.0.1\"," >> $Agent_Config_File
            echo "        \"port\": 8000," >> $Agent_Config_File
            echo "        \"verify_false\": false" >> $Agent_Config_File
            echo "    }" >> $Agent_Config_File
            echo "}" >> $Agent_Config_File
            ;;
        "Ledger")
            Random_String=`head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64 ; echo ''`
            if [ ! -d ../lib/config ]; then
                mkdir ../lib/config
            fi
            mkdir ../lib/config/ledger
            API_Config_File="../lib/config/ledger/config.json"
            echo "{" > $API_Config_File
            echo "    \"web-app\": {" >> $API_Config_File
            echo "        \"debug\": false," >> $API_Config_File
            echo "        \"host\": \"127.0.0.1\"," >> $API_Config_File
            echo "        \"port\": 8000," >> $API_Config_File
            echo "        \"certificate-file\": \"../certs/certificate.crt\"," >> $API_Config_File
            echo "        \"key-file\": \"../certs/privateKey.key\"," >> $API_Config_File
            echo "        \"api-secret\": \"$Random_String\"," >> $API_Config_File
            echo "        \"api-validity-minutes\": 60," >> $API_Config_File
            echo "        \"api-max-calls\": 10," >> $API_Config_File
            echo "        \"api-period-in-seconds\": 60" >> $API_Config_File
            echo "    }" >> $API_Config_File
            echo "}" >> $API_Config_File
            ;;
        "PostgreSQL Database")
            install_database
            ;;
        "Quit")
            printf "\xE2\x9C\x94 Quitting.\n"
            break
            ;;
        *) break;;
    esac
done
