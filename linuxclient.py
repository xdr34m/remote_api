import requests,os,time,socket,argparse,hashlib,logging,sys,subprocess,re,pwd,shutil,grp,random
from dotenv import load_dotenv
from crontab import CronTab
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#servervars
server_url="https://sysman.marksys.de:443/rdir/api"
verify_ssl=False
server_auth=HTTPBasicAuth("user","pw")
#set vars
oprs="rhel"
sign="none"
client_directory="/etc/alloy"


alloy_debug_port=10310
alloy_interface_ip="127.0.0.1"
alloy_user="alloy"

script_exporter_interface_ip="127.0.0.1"
script_exporter_port="10311"
script_exporter_sysconfigfile="/etc/sysconfig/script_exporter.config"
script_exporter_hardconfigfile="/etc/alloy/files/std_script_exporter_config.yaml"

# LogRotate, only needed under linux
log_file = "/var/log/alloy_updater_client.log"
log_max_size = 5 * 1024 * 1024  # 5 MB
log_backup_count = 4
log_max_age_days = 30
#rhel vars:
tmp_dir="/tmp"#tmp dir for rpm download
build_type="amd64_rpm"#build type
service_name="alloy.service"#service name
data_path="/var/lib/alloy/data" #here the wal is saved #TODO - Check for WAL with Diskspace in Mind
alloy_sysconfig_file="/etc/sysconfig/alloy" #here are env vars for the unitfile
rpm_name="alloy"#rpm-name
script_exporter_rpm_name="script_exporter"
updater_client_name="alloy_updater_client"
alloy_config_rootdir="/etc/alloy"
cron_command = f"{alloy_config_rootdir}/{updater_client_name} >> {log_file}"
cron_schedule = "*/30 * * * *"  # Jede 30 Minuten
cron_user="root"
cron_comment = "alloy_updater_client" #cron comment - used to identify
linux_uid=2065
linux_gid=2065
rand_delay_executing_s=600 #delay executing randomly by 0 to 600s - need to be a bit lower than cron interval! #0-10min on top of 30m so max 40m for sync

def parseargs():
    parser = argparse.ArgumentParser(description='A great argparse function example.')
    parser.add_argument('-reinstall','--reinstall',action='store_true',required=False,help='if set, deletes alloy and reinstalls it')
    parser.add_argument('-deinstall','--deinstall',action='store_true',required=False,help='if set, deletes alloy')
    parser.add_argument('-dbg','--debug',action='store_true',required=False,help='if set uses debug_dir where the script resides and logs debug')
    parser.add_argument('-nodelay','--norandomdelay',action='store_true',required=False,help='if set no sleep before executing')
    
    # Parsing arguments and returning
    return parser.parse_args()

def change_config_variable(file_path, variable_name, new_value):
    with open(file_path, 'r') as file:
        content = file.read()
    # Regex to find the variable and change its value
    pattern = re.compile(rf'({variable_name}\s*=\s*).*')
    if pattern.search(content):
        new_content = pattern.sub(rf'\1{new_value}', content)#care removed ""
    else:
        # Add the variable if it doesn't exist
        new_content = content + f'\n{variable_name} = {new_value}' #care removed ""
    with open(file_path, 'w') as file:
        file.write(new_content)

def get_all_files_with_filenames(root_dir):
    all_files = []
    for root, _, files in os.walk(root_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            if os.path.isfile(filepath):
                all_files.append(filepath)
    return all_files

def generate_file_hash(file_path, hash_algorithm='sha256'):
    hash_func = hashlib.new(hash_algorithm)
    
    with open(file_path, 'rb') as f:
        chunk = f.read(8192)
        while chunk:
            hash_func.update(chunk)
            chunk = f.read(8192)
    
    return hash_func.hexdigest()

def fetch_server_versions(oprs,hostname,sign,server_url):
    try:
        if sign!=None:
            response = requests.post(f'{server_url}/check_updates', json={'hostname': hostname, 'operatingsystem': oprs,'need_signed_scripts': sign},verify=verify_ssl, auth=server_auth)
        else:
            response = requests.post(f'{server_url}/check_updates', json={'hostname': hostname, 'operatingsystem': oprs},verify=verify_ssl, auth=server_auth)
        response.raise_for_status()
        logger.debug(f"server_versions: {response.json()}")
        return response.json()
    except requests.exceptions.RequestException as e:
        try:
            logger.error(response.text)
        except Exception:
            logger.error(f"Error fetching server versions: {e}")
            return {}
        logger.error(f"Error fetching server versions: {e}")
        return {}

def get_local_versions(directory_to_watch,alloy_root_dir): 
    def add_nested_key(dictionary, keys, value):
        sub_dict = dictionary
        for key in keys[:-1]:
            if key not in sub_dict:
                sub_dict[key] = {}
            sub_dict = sub_dict[key]
        sub_dict[keys[-1]] = value
    def add_empty_dirs(dictionary, root_dir):
        for root, dirs, files in os.walk(root_dir):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                path_list = dir_path.split(os.sep)
                folder = path_list[-1]
                add_nested_key(dictionary, ["dirs", folder], {})
    local_file_versions={}
    try:
        root_dir=os.path.join(alloy_root_dir,directory_to_watch)
        add_empty_dirs(local_file_versions, root_dir)
        for root, _, files in os.walk(root_dir):
            for filename in files:
                filepath:str = os.path.join(root, filename) # the filenames gets appended maybe thats not working when dir is empty - cause some function needs the filename? but which
                if os.path.isfile(filepath):
                    """extract keys by path"""
                    path_list = filepath.split(os.sep)
                    folder=path_list[-2]
                    # Ignore files at the base level of the directory
                    if root == root_dir:
                        continue
                    if filename==".env" or filename[:4]=="cus_":
                        continue
                    add_nested_key(local_file_versions,["dirs",folder,filename],generate_file_hash(filepath))
        logger.debug(f"local_file_versions: {local_file_versions}")
        return local_file_versions

    except Exception as e:
        #add logging here 
        return None

def compare_dicts(local: dict, remote: dict):
    changes = {}

    def compare(local, remote, path=""):
        for key in remote:
            new_path = f"{path}/{key}" if path else key
            if key not in local:
                changes[new_path] = {"status": "missing_in_local", "remote_value": {key: remote[key]} if not isinstance(remote[key], dict) else remote[key]}
            elif isinstance(remote[key], dict) and isinstance(local[key], dict):
                compare(local[key], remote[key], new_path)
            elif remote[key] != local[key]:
                changes[new_path] = {"status": "hash_mismatch", "local_value": {key: local[key]} if not isinstance(local[key], dict) else local[key], "remote_value": {key: remote[key]} if not isinstance(remote[key], dict) else remote[key]}

        for key in local:
            new_path = f"{path}/{key}" if path else key
            if key not in remote:
                changes[new_path] = {"status": "extra_in_local", "local_value": {key: local[key]} if not isinstance(local[key], dict) else local[key]}

    # Entfernen von Basis-Schlüsseln, die nicht 'dirs' sind
    keys_to_remove = [key for key in remote if key != 'dirs']
    for key in keys_to_remove:
        remote.pop(key)

    #print("DEBUGLOCAL in COMPARE:", local)
    #print("DEBUGREMOTE in COMPARE:", remote)
    compare(local, remote)
    logger.debug(f"changes: {changes}")
    return changes

def local_actions(file_changes,client_directory,oprs,hostname,sign,server_url,alloy_root_dir,alloy_debug_port:int=12345,alloy_interface_ip:str="127.0.0.1")->None:
    def download_and_replace_file(path, client_directory,filename,oprs,hostname,sign)->None:
        try:
            # Hier wird angenommen, dass der Dateiname der letzte Teil des Pfades ist‚
            #filename = os.path.basename(path)
            #logger.debug(f"PATH: {path} Filename: {filename}")
            try:
                subfolder=path.split(os.sep)[1]
                #print(f"d+r:SUBFOLDER NORMAL so: {subfolder} and file: {filename}")
            except IndexError:
                subfolder=path.split(os.sep)[0] # this does only a half fix... idk
                #print(f"d+r:SUBFOLDER GOT INDEXERROR so backup: {subfolder} and file: {filename}") #this isnt triggered :O
            # Erstellen Sie den vollständigen Pfad zur Datei
            file_path = os.path.join(alloy_root_dir,client_directory,subfolder, filename)
            # URL zum Herunterladen der Datei (dies ist ein Beispiel, passen Sie es an Ihre Bedürfnisse an)
            url = f'{server_url}/download/files/{oprs}/{hostname}/{subfolder}/{sign}/{filename}'
            response = requests.get(url,verify=verify_ssl, auth=server_auth)
            response.raise_for_status()
            # Schreiben Sie den Inhalt in die Datei
            with open(file_path, 'wb') as file:
                file.write(response.content)
            logger.info(f"Downloaded and re/placed file: {file_path}")
            if subfolder=="scripts":
                command=["chmod","+x",file_path]
                stdout,stderr,rc=linux_shell_command(command)
                if rc==0:
                    logger.info("Script chmod+x success")
                else:
                    logger.error("Script chmod+x failed")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading file {filename}: {e}")
    
    def delete_local_file(path:str, client_directory,filename)->None:
        try:
            # Hier wird angenommen, dass der Dateiname der letzte Teil des Pfades ist
            subfolder=path.split(os.sep)[1]
            #debug
            #print("DEL:SUBFOLDER",subfolder,"filename:",filename)
            # Erstellen Sie den vollständigen Pfad zur Datei
            file_path = os.path.join(alloy_root_dir,client_directory,subfolder, filename)
            os.remove(file_path)
            logger.info(f"Deleted file: {file_path}")
        except OSError as e:
            logger.error(f"Error deleting file {filename}: {e}")

    #debug
    #print("FILE_CHANGES DEBUG",file_changes)
    reload_needed=False
    for path, change in file_changes.items():
        #print("LOOPPRINT DEBUG: PATH:", path,"change:", change)
        if change['status'] == 'missing_in_local' or change['status'] == 'hash_mismatch':
            for file in change['remote_value']:
                download_and_replace_file(path, client_directory,file,oprs,hostname,sign)
        elif change['status'] == 'extra_in_local':
            for file in change['local_value']: # the trick is if local_value is empty the Loop gets executed 0 times so empty folders dont get deled
                delete_local_file(path, client_directory,file)
                #print("DETECT STRANGE VALUE OF file:",file)
        if change['status']=="missing_in_local" or change['status'] == 'hash_mismatch' or change["status"]=="extra_in_local":
            reload_needed=True
    if reload_needed:
        reload_alloy_service(alloy_interface_ip,alloy_debug_port)
        #restarting script_exporter # 
        script_exporter_configcheck_restart()

def reload_alloy_service(interface_ip:str="127.0.0.1",alloy_debug_port:int=12345,http_startup_time_wait_s:int=2)->None:
    try:
        response = requests.get(f'http://{interface_ip}:{alloy_debug_port}/-/reload')
        response.raise_for_status()
        #logger.info("Alloy config reloaded")
        
        if response.text.strip() != "config reloaded":
            logger.info(f"Failed reloading alloy service with http:\n {response.text}")
        else:
            logger.info(response.text)
        #do something if the response is config reload failed config fault
    except Exception as e:
        logger.info(f"Failed reloading alloy service with http {repr(e)} ...trying to reloading service")
        try:
            logger.warning(f"Alloy config error: {response.text}")
            if response.status_code==400:
                logger.info(f"Im not reloading the service, config seems broken!")
                return 0
        except UnboundLocalError:
            pass
        command=["systemctl","reload","alloy"]
        stdout,stderr,rc=linux_shell_command(command)
        if rc==0:
            logger.info("Alloy service reloaded")
        else:  
            logger.info(f"Failed reloading alloy service: {stdout.rstrip()}{stderr.rstrip()} ... trying to start")
            command=["systemctl","start","alloy"]
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Alloy service started waiting {http_startup_time_wait_s}sec for http-service check")
                time.sleep(http_startup_time_wait_s)
                try:
                    response = requests.get(f'http://{interface_ip}:{alloy_debug_port}')
                    response.raise_for_status()
                except Exception as e:
                    logger.warning(f"Alloy service did not start within {http_startup_time_wait_s}sec, waiting another {http_startup_time_wait_s*2}sec for http-service check")
                    time.sleep(http_startup_time_wait_s*2)
                    try:
                        response = requests.get(f'http://{interface_ip}:{alloy_debug_port}')
                        response.raise_for_status()
                    except Exception as e:
                        logger.error(f"http service 'http://{interface_ip}:{alloy_debug_port}' didnt came up ... giving up")
                        return 0
                logger.info("Alloy http service up and serving!")
            else:
                logger.error(f"Failed starting alloy service: {stdout.rstrip()}{stderr.rstrip()} ... giving up")
            
def linux_shell_command(command:list):
    """
    Install a rpm file with options
    """
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return result.stdout, result.stderr, result.returncode

def modify_service_variable_systemctl(service_name, variable_name, new_value):
    # Find the service file location
    command = ["systemctl", "cat", service_name]
    stdout, stderr, rc = linux_shell_command(command)
    if rc != 0:
        logger.error(f"Error finding service file: {stderr}")
        return False

    # Extract the file path from the output
    match = re.search(r'^# (\S+)', stdout, re.MULTILINE)
    if not match:
        logger.error("Service file path not found")
        return False

    service_file_path = match.group(1)

    # Read the service file
    with open(service_file_path, 'r') as file:
        lines = file.readlines()

    # Modify the specified variable
    new_lines = []
    for line in lines:
        if line.startswith(variable_name):
            line = f"{variable_name}={new_value}\n"
        new_lines.append(line)

    # Write the modified content back to the service file
    with open(service_file_path, 'w') as file:
        file.writelines(new_lines)

    return True

def rotate_logfile(log_file, max_size, backup_count, max_age_days,user):
    """
    Rotiert die Logdatei, wenn sie eine bestimmte Größe überschreitet, und löscht alte Backups.
    Erstellt die Logdatei, wenn sie nicht vorhanden ist, und setzt den Eigentümer auf den angegebenen Benutzer.

    :param log_file: Pfad zur Logdatei.
    :param max_size: Maximale Größe der Logdatei in Bytes.
    :param backup_count: Anzahl der Backup-Dateien, die behalten werden sollen.
    :param max_age_days: Maximales Alter der Backup-Dateien in Tagen.
    :param user: Benutzername, dem die Logdatei gehören soll.
    """
    if not os.path.exists(log_file):
        # Logdatei erstellen und Eigentümer setzen
        open(log_file, 'a').close()
        uid = pwd.getpwnam(user).pw_uid
        gid = pwd.getpwnam(user).pw_gid
        os.chown(log_file, uid, gid)
        logger.info(f"Created {log_file} and set to {user}")

    if os.path.exists(log_file) and os.path.getsize(log_file) > max_size:
        # Rotieren der Logdatei
        for i in range(backup_count - 1, 0, -1):
            src = f"{log_file}.{i}"
            dst = f"{log_file}.{i + 1}"
            if os.path.exists(src):
                shutil.move(src, dst)
        shutil.move(log_file, f"{log_file}.1")
        if not os.path.exists(log_file):
            # Logdatei erstellen und Eigentümer setzen
            open(log_file, 'a').close()
            uid = pwd.getpwnam(user).pw_uid
            gid = pwd.getpwnam(user).pw_gid
            os.chown(log_file, uid, gid)
            logger.info(f"Created {log_file} and set to {user}")


    # Löschen alter Backup-Dateien
    now = datetime.now()
    for i in range(1, backup_count + 1):
        backup_file = f"{log_file}.{i}"
        if os.path.exists(backup_file):
            file_mtime = datetime.fromtimestamp(os.path.getmtime(backup_file))
            if now - file_mtime > timedelta(days=max_age_days):
                os.remove(backup_file)

def check_for_rpmupdates(server_url,oprs,reinstall=None,logfile=None,alloy_std_port=12345,interface_ip="127.0.0.1",alloy_user="alloy",alloy_config_rootdir="/etc/alloy",alloy_home_dir="/var/lib/alloy"):
    def setup_linux_user_group(user,group,uid,gid)->bool:
        def create_group(group_name, gid):
            try:
                subprocess.run(['groupadd', '-g', str(gid), group_name], check=True)
                logger.info(f"Gruppe {group_name} mit GID {gid} erfolgreich erstellt.")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Fehler beim Erstellen der Gruppe: {e}")
                return False
        def create_user(user_name, uid, group_name)->bool:
            try:
                subprocess.run(['useradd','-d',alloy_home_dir,'-s','/bin/false','-r', '-u', str(uid), '-g', group_name, user_name], check=True)
                logger.info(f"Benutzer {user_name} mit UID {uid} und Gruppe {group_name} erfolgreich erstellt.")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Fehler beim Erstellen des Benutzers: {e}")
                return False
        success=create_group(group, gid)
        if not success:
            sys.exit(1)
        success=create_user(user, uid, group)
        if not success:
            sys.exit(1)
        return True
    def modunit_reloadsystemctl_reloadalloy_checkup(service_name): #TODO check if needed without custom storagepath
        modify_service_variable_systemctl(service_name,"ExecStart","/usr/bin/alloy run $CUSTOM_ARGS $CONFIG_FILE")
        command=["systemctl","daemon-reload"]
        stdout,stderr,rc=linux_shell_command(command)
        if rc==0:
            logger.info(f"Alloy unitfile changed & systemctl daemon reloaded")
            command=["systemctl","restart",service_name]
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Alloy reloaded")
                reload_alloy_service(interface_ip,alloy_std_port)
            else:
                logger.error(f"Failed reloading Alloy: {stdout.rstrip()}{stderr.rstrip()}")
        else:
            logger.error(f"Error systemctl daemon reloading after service change: {stdout.rstrip()}{stderr.rstrip()}")
    def check_prepare_data_path(user,group,path)->bool:#TODO - testing for what happens if /var is full :)
        def chown_and_chmod():
            command=["chown","-R",f"{user}:{group}",path]
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Data path {path} chowned to {user}:{group}")
                command=["chmod","g+s,+t",path]
                stdout,stderr,rc=linux_shell_command(command)
                if rc == 0:
                    logger.info(f"Set group sticky bit and sticky bit on {path}")
                else:
                    logger.error(f"Error setting group sticky bit and sticky bit on {path}: {stdout.rstrip()}{stderr.rstrip()}")
            else:
                logger.error(f"Error chowning data path {path}: {stdout.rstrip()}{stderr.rstrip()}")

        user_uid = pwd.getpwnam(user).pw_uid# Get the UID of the user
        group_gid = grp.getgrnam(group).gr_gid# Get the GID of the group
        if os.path.exists(path):
            file_uid = os.stat(path).st_uid# Get the UID of the file/directory
            file_gid = os.stat(path).st_gid# Get the UID of the file/directory
            if user_uid==pwd.getpwnam(user).pw_uid:
                user_owned=True
            if group_gid==grp.getgrnam(group).gr_gid:
                group_owned=True
            if not user_owned or group_owned:
                chown_and_chmod()
        else:
            command=["mkdir","-p",path]
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Data path {path} created")
                chown_and_chmod()
            else:
                logger.error(f"Error creating data path {path}: {stdout.rstrip()}{stderr.rstrip()}")
    def fetch_server_rpmversions(server_url,build_type):
        try:
            response = requests.get(f'{server_url}/check_rpm_updates/{build_type}',verify=verify_ssl, auth=server_auth)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching server rpmversions: {e}")
            return False
    def is_version_greater(version1: str, version2: str):
        def parse_version(version: str):
            return list(map(int, version.split('.')))
        return parse_version(version1) > parse_version(version2)
    def is_version_lower(version1: str, version2: str):
        def parse_version(version: str):
            return list(map(int, version.split('.')))
        return parse_version(version1) < parse_version(version2)

    if reinstall:
        #uninstall code...
        uninstall_script_exporter_rpm(script_exporter_rpm_name)
        success=deinstall_alloy_yum(rpm_name,alloy_config_rootdir,cron_comment,cron_user,alloy_user,alloy_user)
        if not success:
            logger.error("Error deinstalling Alloy, exiting...")
            sys.exit(1)
        
    logger.info("Checking for RPM Updates...")
    command=["rpm","-q","alloy"]
    stdout,stderr,rc=linux_shell_command(command)
    if rc == 0:
        logger.info(f"Alloy is installed: {stdout.rstrip()}")
        alloy_installed=stdout.split("-")[1]
    else:
        logger.info(f"Alloy not installed: {stdout.rstrip()}{stderr.rstrip()}")
        alloy_installed=False
    command=["rpm","-q","script_exporter"]
    stdout,stderr,rc=linux_shell_command(command)
    if rc == 0:
        logger.info(f"script_exporter is installed: {stdout.rstrip()}")
        script_exporter_installed=stdout.split("-")[1]
    else:
        logger.info(f"script_exporter not installed: {stdout.rstrip()}{stderr.rstrip()}")
        script_exporter_installed=False
    if alloy_installed and script_exporter_installed:
        server_updates = fetch_server_rpmversions(f"{server_url}",build_type)
        if not server_updates:
            logger.warning("no Server Versions got, skipping updates")
            return
        if is_version_greater(server_updates["alloy"],alloy_installed):
            logger.info(f"New Version of Alloy available: {server_updates['alloy']}")
            filepath=download_file(f"{server_url}/download/alloy_installer/{build_type}",tmp_dir) # download installer to tmp
            logger.info(f"Alloy downloaded to {filepath}")
            #command=["rpm","-Uvh",filepath] #TODO check if can do via yum: like yum localinstall /tmp/rpm -y, localupgrade, yum downgrade /tmp/rpm #--maybe nogpg
            command = ["yum", "localinstall", "-y", filepath, "--disablerepo=*", "--noplugins"]  # Using yum to install the new version
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Alloy updated to {server_updates['alloy']}")
                #modunit_reloadsystemctl_reloadalloy_checkup(service_name) #TODO test - not needed if std wal path
            else:
                logger.error(f"Error updating Alloy: {stdout.rstrip()}{stderr.rstrip()}")
        elif is_version_lower(server_updates["alloy"],alloy_installed):
            logger.info(f"Older Version of Alloy available: {server_updates['alloy']}")
            filepath=download_file(f"{server_url}/download/alloy_installer/{build_type}",tmp_dir) # download installer to tmp
            logger.info(f"Alloy downloaded to {filepath}")
            #command=["rpm","-Uvh","--oldpackage",filepath] #TODO check if can do via yum: like yum localinstall /tmp/rpm -y, localupgrade, yum downgrade /tmp/rpm #--maybe nogpg
            command = ["yum", "downgrade", "-y", filepath, "--disablerepo=*", "--noplugins"]  # Using yum to downgrade to the older version | maybe need --nogpgcheck
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Alloy downgraded to {server_updates['alloy']}")
                #modunit_reloadsystemctl_reloadalloy_checkup(service_name) #TODO test - not needed if std wal path
            else:
                logger.error(f"Error downgrading Alloy: {stdout.rstrip()}{stderr.rstrip()}")
        else:
            logger.debug("Alloy version is in sync with server")
        if is_version_greater(server_updates["script_exporter"],script_exporter_installed):
            logger.info(f"New Version of Script Exporter available: {server_updates['script_exporter']}")
            download_install_script_exporter_rpm(server_url,build_type)
        elif is_version_lower(server_updates["script_exporter"],script_exporter_installed):
            logger.info(f"Older Version of Script Exporter available: {server_updates['script_exporter']}")
            download_downgrade_script_exporter_rpm(server_url,build_type)
        else:
            logger.debug("script_exporter version is in sync with server")
    else: # executed if alloy not found!
        #preinstall ->setup alloy user+group
        setup_linux_user_group(alloy_user,alloy_user,linux_uid,linux_gid)
        check_prepare_data_path(alloy_user,alloy_user,data_path)
        filepath=download_file(f"{server_url}/download/alloy_installer/{build_type}",tmp_dir) # download installer to tmp
        logger.info(f"Alloy downloaded to {tmp_dir}")
        command=["rpm","-Uvh",filepath]#oldschool
        command = ["yum", "localinstall", "-y", filepath, "--disablerepo=*", "--noplugins"] #, "--nogpgcheck" maybe needed
        stdout,stderr,rc=linux_shell_command(command)
        if rc == 0:
            logger.info(f"Installation erfolgreich!")
            #more code to do on initial install - setting service file correctly and env vars and create the dirs needed
            dirs=["config","files","scripts"]
            for folder in dirs: # Loop creating of subdirs, cant use shell specials like {}
                command=["mkdir","-p",f"{alloy_config_rootdir}/{folder}"]
                stdout,stderr,rc=linux_shell_command(command)
                if rc==0:
                    logger.info(f"Alloy dir {folder} created")
                else:
                    logger.error(f"Error creating alloy dir {folder}: {stdout.rstrip()}{stderr.rstrip()}")
            command=["chown","-R",f"{alloy_user}:{alloy_user}",alloy_config_rootdir]
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Alloy dirs chowned")
            else:
                logger.error(f"Error chowing alloy dirs: {stdout.rstrip()}{stderr.rstrip()}")
            
            install_cronjob_for_user(cron_command, cron_schedule, cron_comment, cron_user)

            change_config_variable(alloy_sysconfig_file,"CONFIG_FILE",'"/etc/alloy/config"')
            change_config_variable(alloy_sysconfig_file,"CUSTOM_ARGS",f'"--disable-reporting --storage.path={data_path} --server.http.memory-addr=alloy.internal:{alloy_std_port} --server.http.listen-addr={interface_ip}:{alloy_std_port}"')
            
            #needsomething to change the wal dir aka storage-path (its in the service file... maybe delete that part and add it via string to custom_args) - exactly this is done now!
            modify_service_variable_systemctl(service_name,"ExecStart","/usr/bin/alloy run $CUSTOM_ARGS $CONFIG_FILE")
            
            command=["systemctl","daemon-reload"]#only needed for alloy
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Alloy unitfile changed & systemctl daemon reloaded")
                """doing script exporter now!"""
                download_install_script_exporter_rpm(server_url,build_type)
            else:
                logger.error(f"Error systemctl daemon reloading after service change: {stdout.rstrip()}{stderr.rstrip()}")
        else:
            logger.error(f"Fehler bei der Installation: {stderr.rstrip()}")
            
def download_file(url, dest_folder):#TODO check if save even on interrupt of stream
    """
    Lädt eine Datei von einer URL herunter und speichert sie im angegebenen Verzeichnis.

    :param url: Die URL der herunterzuladenden Datei.
    :param dest_folder: Das Verzeichnis, in dem die Datei gespeichert werden soll.
    """
    if not os.path.exists(dest_folder):
        logger.error(f"{dest_folder} does not exist")
        #y_or_n=input(f"Enter y to create {dest_folder} or n to exit") #cant ask for user input the way the script is executed
        raise Exception(f"{dest_folder} does not exist")
    with requests.get(url, stream=True,verify=verify_ssl, auth=server_auth) as r:
        r.raise_for_status()
        content_disposition = r.headers.get('content-disposition')
        if content_disposition:
            filename = content_disposition.split('filename=')[1].strip('"')
        else:
            raise Exception("Possible Server Error, no filename in response")
        local_filename = os.path.join(dest_folder, filename)
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return local_filename
    
def deinstall_alloy_yum(rpm_name,alloy_config_rootpath,cron_comment,cron_user,alloy_user,alloy_group)->bool:
    #check if alloy is installed
    command=["rpm","-q","alloy"]
    stdout,stderr,rc=linux_shell_command(command)
    if rc == 0:
        logger.info(f"Alloy is installed: {stdout.rstrip()}")
        installed=stdout.split("-")[1]
    else:
        logger.info(f"Alloy not installed: {stdout.rstrip()}{stderr.rstrip()}... cant use --reinstall or --deinstall")
        return False
    # Stop the service - gracefully - if it is running
    service_name = "alloy.service"
    command = ["systemctl", "stop", service_name]
    stdout, stderr, rc = linux_shell_command(command)
    if rc == 0:
        logger.info(f"{service_name} stopped successfully")
    else:
        logger.warning(f"Error stopping {service_name}: {stdout.rstrip()}{stderr.rstrip()}, but continouing with deinstall")

    command=["rpm","-e","--nodeps",rpm_name] #oldschool
    command = ["yum", "remove", "-y", rpm_name, "--disablerepo=*", "--noplugins"] #yummie
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"Alloy deinstalled")
        command=["rm","-rf",alloy_config_rootpath]
        stdout,stderr,rc=linux_shell_command(command)
        if rc==0:
            logger.info(f"Alloy config dir deleted")
            delete_cronjob_for_user(cron_comment,cron_user)
            command=["userdel",alloy_user]
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Deleted User: {alloy_user}")
                command=["groupdel",alloy_group]
                stdout,stderr,rc=linux_shell_command(command)
                if rc==0:
                    logger.info(f"Deleted Group: {alloy_group}")
                    return True
                else:
                    if stderr.strip()==f"groupdel: group '{alloy_user}' does not exist":
                        logger.info(f"Group could not be deleted, cause it doesnt exist, this is fine!")
                    else:
                        logger.error(f"Group deletion failed group: {alloy_group} stdout:{stdout.rstrip()} stderr:{stderr.rstrip()}")
            else:
                logger.error(f"User deletion failed user: {alloy_user} {stdout.rstrip()} {stderr.rstrip()}")
        else:
            logger.error(f"Error deleting Alloy config dir: {stdout.rstrip()}{stderr.rstrip()}, but is uninstalled! - delete config manually (will be resyned next intervall)")
            delete_cronjob_for_user(cron_comment,cron_user)
            command=["userdel","-r",alloy_user]
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Deleted User: {alloy_user}")
                command=["groupdel","-r",alloy_group]
                stdout,stderr,rc=linux_shell_command(command)
                if rc==0:
                    logger.info(f"Deleted Group: {alloy_group}")
                    return True
                else:
                    logger.error(f"Group deletion failed group: {alloy_group}")
            else:

                logger.error(f"User deletion failed user: {alloy_user}")
            return True
        #cant use confirmation here.. cause of special shell command to execute ---wget -qO- http://lxsyspy01-s01:8080/download/initial_install/rhel/true | bash -c 'cat > /tmp/temp_binary && chmod +x /tmp/temp_binary && sudo /tmp/temp_binary && sudo mv /tmp/temp_binary /etc/alloy/alloy_updater_client
        """input_confirm=input(f"Type y and enter, to continue deleting config dir: {alloy_config_rootpath}")
        if input_confirm=="y":
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info(f"Alloy config dir deleted")
                return True
            else:
                logger.error(f"Error deleting Alloy config dir: {stdout}{stderr}, but is uninstalled! - delete config manually")
                return True"""
        logger.info(f"Deleted {alloy_config_rootpath}")
        return True
    else:
        logger.error(f"Error deinstalling Alloy: {stdout.rstrip()}{stderr.rstrip()}")
        return False
        
def install_cronjob_for_user(command, schedule, comment, user, cron_file="/etc/cron.d/alloy_updater"): #/etc/cron.d/alloy_updater not ins crontab schreiben!
    """
    Installiert einen Cronjob für einen bestimmten Benutzer, wenn er noch nicht existiert.

    :param command: Der Befehl, der ausgeführt werden soll.
    :param schedule: Der Zeitplan für den Cronjob (z.B. '* * * * *' für jede Minute).
    :param comment: Ein Kommentar, um den Cronjob zu identifizieren.
    :param user: Der Benutzer, für den der Cronjob installiert werden soll.
    """
    if not os.path.exists(cron_file):
        logger.info(f"Cronfile {cron_file} does not exist -> creating")
        with open(cron_file, 'w') as file:
            file.write(f"# Cronjobs for alloy\n")
    # Benutzer-Crontab laden
    cron = CronTab(tabfile=cron_file,user=False)
    # Überprüfen, ob der Cronjob bereits existiert
    job_exists = any(job for job in cron if job.comment == comment or job.command == command)
    if job_exists:
        logger.info(f"Cronjob '{comment}' für Benutzer '{user}' existiert bereits.")
        return
    # Neuen Cronjob erstellen
    job = cron.new(command=command, comment=comment,user=user)
    # Zeitplan festlegen
    job.setall(schedule)
    # Cronjob speichern
    cron.write()

    logger.info(f"Cronjob '{comment}' für Benutzer '{user}' installiert: {schedule} {command}")

def delete_cronjob_for_user(comment, user, cron_file="/etc/cron.d/alloy_updater"):
    """
    Löscht einen Cronjob für einen bestimmten Benutzer basierend auf dem Kommentar.

    :param comment: Der Kommentar, der den Cronjob identifiziert.
    :param user: Der Benutzer, für den der Cronjob gelöscht werden soll.
    """
    # Benutzer-Crontab laden
    cron = CronTab(tabfile=cron_file,user=False)

    # Cronjob suchen und löschen
    jobs = list(cron.find_comment(comment))
    if not jobs:
        logger.info(f"Kein Cronjob mit dem Kommentar '{comment}' für Benutzer '{user}' gefunden.")
        return

    for job in jobs:
        cron.remove(job)
        logger.info(f"Cronjob '{comment}' für Benutzer '{user}' gelöscht.")

    # Änderungen speichern
    cron.write()

def install_script_exporter_linux_bin(server_url,build_type,client_directory="/etc/alloy",alloy_user="alloy",alloy_group="alloy",interface="127.0.0.1",port=9469,config_path="std_script_exporter_config.yaml"):#old
    #TODO Create a rpm file out of the binary, to have history logging of yum installs upgrades removes :)
    unitfile_path="/usr/lib/systemd/system/script_exporter.service"
    env_file="/etc/sysconfig/script_exporter"
    with open(env_file,"w") as file:
        file.write(f'CUSTOM_ARGS=-config.file "{config_path}" -web.listen-address "{interface}:{port}"')
    logger.info(f"{env_file} written")
    filepath=download_file(f"{server_url}/download/script_exporter/{build_type}",client_directory) #download the binary to alloy_dir
    logger.info(f"{filepath} downloaded")
    unitfile=f"""
[Unit]
Description=Script Exporter
Documentation=https://github.com/ricoberger/script_exporter
Wants=network-online.target
After=network-online.target

[Service]
Restart=always
User={alloy_user}
EnvironmentFile=/etc/sysconfig/script_exporter
WorkingDirectory={client_directory}
ExecStart={filepath} $CUSTOM_ARGS  
TimeoutStopSec=20s

[Install]
WantedBy=multi-user.target
"""

    with open(unitfile_path,"w") as file:#write the unitfile
        file.write(unitfile)
    logger.info(f"{unitfile_path} written")
    command=["systemctl","daemon-reload"] # isnt done, should be already done in rpm_check where is is executed
    command=["chmod","+x",filepath]
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"chmod +x success")
    else:
        logger.error(f"chmod +x failed {stdout.rstrip()} {stderr.rstrip()}")

def uninstall_script_exporter_linux_bin(client_directory="/etc/alloy",alloy_user="alloy",alloy_group="alloy",interface="127.0.0.1",port=9469,config_path="/etc/alloy/files/script_exporter_config.yaml"):#old
    unitfile_path="/usr/lib/systemd/system/script_exporter.service"
    env_file="/etc/sysconfig/script_exporter"
    command=["systemctl","stop","script_exporter"]
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"script_exporter stopped")
    else:
        logger.warning(f"Error stopping script_exporter: {stdout.rstrip()}{stderr.rstrip()}, but continouing with deinstall")
    command=["systemctl","disable","script_exporter"]
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"script_exporter disabled")
    else:
        logger.warning(f"Error disabling script_exporter: {stdout.rstrip()}{stderr.rstrip()}, but continouing with deinstall")
    command=["rm","-f",unitfile_path]
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"script_exporter unitfile deleted")
    else:
        logger.error(f"Error deleting script_exporter unitfile: {stdout.rstrip()}{stderr.rstrip()}")
    command=["rm","-f",env_file]
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"script_exporter envfile deleted")
    else:
        logger.error(f"Error deleting script_exporter envfile: {stdout.rstrip()}{stderr.rstrip()}")
    command=["rm","-f",f"{client_directory}/script_exporter"]
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"script_exporter binary deleted")
    else:
        logger.error(f"Error deleting script_exporter binary: {stdout.rstrip()}{stderr.rstrip()}")
    return True

def download_install_script_exporter_rpm(server_url,build_type,download_path="/tmp",client_directory="/etc/alloy",interface="127.0.0.1",port=9469):
    command=["mkdir","-p",download_path]
    stdout,stderr,rc=linux_shell_command(command)
    filepath=download_file(f"{server_url}/download/script_exporter/{build_type}",download_path) # download installer to tmp
    command = ["yum", "localinstall", "-y", filepath, "--disablerepo=*", "--noplugins"]  # Using yum to install the new version
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"Installed {filepath} via yum localinstall")
        change_config_variable(script_exporter_sysconfigfile,"CUSTOM_ARGS",f"-config.file '{script_exporter_hardconfigfile}' -web.listen-address '{script_exporter_interface_ip}:{script_exporter_port}'")
        return True
    else:
        logger.error(f"Install of {filepath} failed with {stdout.rstrip()} {stderr.rstrip()}")
        return False
    
def download_downgrade_script_exporter_rpm(server_url,build_type,download_path="/tmp",client_directory="/etc/alloy",interface="127.0.0.1",port=9469):
    command=["mkdir","-p",download_path]
    stdout,stderr,rc=linux_shell_command(command)
    filepath=download_file(f"{server_url}/download/script_exporter/{build_type}",download_path) # download installer to tmp
    command = ["yum", "downgrade", "-y", filepath, "--disablerepo=*", "--noplugins"]  # Using yum to downgrade to the older version | maybe need --nogpgcheck
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"Downgraded {filepath} via yum downgrade")
        change_config_variable(script_exporter_sysconfigfile,"CUSTOM_ARGS",f"-config.file '{script_exporter_hardconfigfile}' -web.listen-address '{script_exporter_interface_ip}:{script_exporter_port}'")
        return True
    else:
        logger.error(f"Downgrading  of {filepath} failed with {stdout.rstrip()} {stderr.rstrip()}")
        return False
    
def uninstall_script_exporter_rpm(script_exporter_rpm_name):
    command=["rpm","-q","script_exporter"]
    stdout,stderr,rc=linux_shell_command(command)
    if rc == 0:
        logger.info(f"script_exporter is installed: {stdout.rstrip()}")
        script_exporter_installed=stdout.split("-")[1]
    else:
        logging.info(f'script_exporter is not installed ')
    command = ["yum", "remove",script_exporter_rpm_name, "-y", "--disablerepo=*", "--noplugins"]  # Using yum to remove package
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info(f"Removed package script_exporter via yum remove")
        return True
    else:
        logger.warning(f"Remove of script_exporter package failed with {stdout.rstrip()} {stderr.rstrip()}")
        return False

def script_exporter_configcheck_restart(alloy_root_path="/etc/alloy",sysconfigfile="/etc/sysconfig/script_exporter.config",binpath="/usr/bin/script_exporter",hardconfig="script_exporter_config.yaml"):#TODO change sysconfig with hardlink
    configcheck_option="-config.check"
    configfile_option="-config.file"
    if not load_dotenv(sysconfigfile,override=True):
        logger.error(f"Coudnt get env from {sysconfigfile}")
    else:
        configfile=os.getenv("CUSTOM_ARGS").replace('"','').replace('-config.file ',"")

    command=[binpath,configcheck_option,configfile_option,script_exporter_hardconfigfile]
    stdout,stderr,rc=linux_shell_command(command)
    if rc==0:
        logger.info("script_exporter config working")
        command=["systemctl","restart","script_exporter"]
        stdout,stderr,rc=linux_shell_command(command)
        if rc==0:
            logger.info("script_exporter restarted")
        else:
            logger.error(f"Restarting script_exporter failed  {stdout.rstrip()} {stderr.rstrip()}")
    else:
        logger.info(f"script_exporter config not valid or not found {command} {stdout.rstrip()} {stderr.rstrip()} ... trying to fix! ")
        filepaths=get_all_files_with_filenames(os.path.join(alloy_root_path,"files"))
        tryoutpath=""
        for filepath in filepaths:
            if filepath.endswith("script_exporter_config.yaml"):
                tryoutpath=filepath
                break
        change_config_variable(script_exporter_sysconfigfile,"CUSTOM_ARGS",f"-config.file '{script_exporter_hardconfigfile}' -web.listen-address '{script_exporter_interface_ip}:{script_exporter_port}'")
        if not load_dotenv(sysconfigfile,override=True):
            logger.error(f"Coudnt get env from {sysconfigfile}")
        else:
            configfile=os.getenv("CUSTOM_ARGS").replace('"','').replace('-config.file ',"")
        command=[binpath,configcheck_option,configfile_option,script_exporter_hardconfigfile]
        stdout,stderr,rc=linux_shell_command(command)
        if rc==0:
            logger.info("script_exporter config working")
            command=["systemctl","restart","script_exporter"]
            stdout,stderr,rc=linux_shell_command(command)
            if rc==0:
                logger.info("script_exporter restarted")
            else:
                logger.error(f"Restarting script_exporter failed {stdout.rstrip()} {stderr.rstrip()}")
        else:
            logger.warning(f"script_exporter config still not valid or not found {command} {stdout.rstrip()} {stderr.rstrip()} ... giving up!")

def script_exporter_updatecheck_update(server_url,build_type)->str: # maybe leave this for now, and doing a check for alloy and for scriptexporter together. Install should be good enough if update needed
    0

def main(reinstall:bool):
    # Erfassen der Startzeit
    start_time = time.time()
    args=parseargs() # parse args
    global client_directory
    logger.info(f"Starting up... waited {random_delay}s")

    """alloy_root_dir = os.path.dirname(os.path.abspath(__file__)) # absolute path of the script without filename
    alloy_root_dir = "/etc/alloy"""
    #load env variables this doesnt work when directly executing from download or setting vars before - or load from an . env file previously downloaded! 
    """load_dotenv(os.path.join(alloy_root_dir,'.env'))
    oprs=os.getenv("REMOTEDIR_OPRS")
    sign=os.getenv("REMOTEDIR_SIGN")
    server_url=os.getenv("SERVER_URL")"""
    #DEBUG

    #globals!
    global sign
    """Vars have to be set somehow"""
    #local_actions_dir_depth=int(os.getenv("LOCAL_ACTIONS_DIR_DEPTH")) # maybe not used
    #print(local_actions_dir_depth)
    if sign.lower() == "none":
        sign=None
    elif sign.lower() == "true":
        sign=True
    elif sign.lower() == "false":
        sign=False
    hostname=socket.gethostname().split(".")[0]
    logger.debug(f"Hostname: {hostname} OS: {oprs}")

    check_for_rpmupdates(server_url,oprs,reinstall,log_file,alloy_debug_port,alloy_interface_ip,alloy_user,client_directory)

    local_files=get_local_versions(client_directory,alloy_config_rootdir)
    #logger.debug(f"local: {local_files}")
    remote_files=fetch_server_versions(oprs,hostname,sign,server_url)
    #logger.debug(f"remote: {remote_files}")
    if remote_files:
        file_changes=compare_dicts(local_files,remote_files)
        # Entfernen von Einträgen mit leerem local_value
        keys_to_remove = [key for key, value in file_changes.items() if 'local_value' in value and value['local_value'] == {}]
        for key in keys_to_remove:
            del file_changes[key]
        # Loggen des Werts von file_changes oder "no changes"
        if file_changes:
            logger.debug(f"Remote_dir: changes: {file_changes}")
        else:
            logger.info("Remote_dir: no changes or no reachable")
        local_actions(file_changes,client_directory,oprs,hostname,sign,server_url,alloy_config_rootdir,alloy_debug_port,alloy_interface_ip)
    else:
        logger.error("got no remote_files skipping next steps")

    #check if alloy is running
    try:
        response = requests.get(f'http://{alloy_interface_ip}:{alloy_debug_port}')
        response.raise_for_status()
    except Exception as e:
        if reinstall:
            logger.info("Alloy not running, this is normal after updating/downgrading - trying to reload/start")
        else:
            logger.warning("Alloy not running, this is not normal - trying to reload/start")
        reload_alloy_service(alloy_interface_ip,alloy_debug_port)

    #check if script exporter is running
    try:
        response = requests.get(f'http://{script_exporter_interface_ip}:{script_exporter_port}')
        response.raise_for_status()
    except Exception as e:
        if reinstall:
            logger.info("script_exporter not running, this is normal after updating/downgrading - trying to reload/start")
            script_exporter_configcheck_restart()
        else:
            logger.warning("script_exporter not running, this is not normal except if newly installed! - trying to reload/start")
            script_exporter_configcheck_restart()
    # Erfassen der Endzeit
    end_time = time.time()
    # Berechnen und protokollieren der Laufzeit
    elapsed_time = end_time - start_time
    logger.info(f"done! took: {elapsed_time:.2f}s")
    if oprs=="rhel":
        rotate_logfile(log_file, log_max_size, log_backup_count, log_max_age_days,alloy_user)
    else:
        pass
    
if __name__ == '__main__':
    #map
    args=parseargs()
    #SET Vars based on debug or not
    if args.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s") # set standart to debug for dev
    #setup logging
    global logger
    logger=logging.getLogger('my_logger')
    if args.deinstall:
        uninstall_script_exporter_rpm(script_exporter_rpm_name)
        success=deinstall_alloy_yum(rpm_name,alloy_config_rootdir,cron_comment,cron_user,alloy_user,alloy_user)
        sys.exit(0)
    if args.norandomdelay: #Normally Script waits for rand intervall if norandomdelay is passed, skipping
        random_delay = 0
    else:
        random_delay = random.randint(0, rand_delay_executing_s)
        time.sleep(random_delay)
    if args.reinstall:
        main(True)
    else:
        logger.debug("Starting main")
        main(False)
