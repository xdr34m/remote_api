import requests.auth
import argparse,sys,subprocess,os,time,random,logging.handlers, shutil, requests, socket, hashlib, re,structlog,traceback
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Globale Variablen


#install/download: powershell -Command "& {Write-Host 'Download started...'; Invoke-WebRequest -Uri 'https://sysman.marksys.de:443/rdir/api/download/initial_install/win/false' -OutFile $env:TEMP\AlloyUpdaterClient.exe -Headers @{Authorization=('Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('supersave:yyZIvh5G6PygERPpFlRqUtOSeTzkxKKoO4jsoHB4x7')))}; Write-Host 'Download finished.'; Start-Process $env:TEMP\AlloyUpdaterClient.exe -Wait; Write-Host 'Execution finished.'; Remove-Item -Path $env:TEMP\AlloyUpdaterClient.exe; Write-Host 'File deleted.'}"

#servervars
server_url="https://sysman.marksys.de:443/rdir/api"
verify_ssl=False
server_auth=HTTPBasicAuth("windows","Y61ZOxXXLOmXCiDsXE7h00sRBDgi9UgJ0N9eIlRQD0")

alloy_config_rootdir = "D:\\Grafana-Alloy"
tmp_dir = "D:\\temp"  # tmp dir for rpm download # not rly used except for the WAL
build_type = "amd64_exe"  # build type
alloy_service_name = "GrafanaAlloy"  # service name
data_path = f"{alloy_config_rootdir}\\alloy-data"  # here the wal is saved
#alloy_sysconfig_file = "C:\\alloy\\sysconfig\\alloy"  # here are env vars for the unitfile
#script_exporter_sysconfig_file = "C:\\alloy\\sysconfig\\script_exporter.config"
alloy_config_dir = f"{alloy_config_rootdir}\\config"
alloy_interface = "127.0.0.1"
alloy_debug_port = "10310"
alloy_exe_path = f"{alloy_config_rootdir}\\alloy_amd64.exe"  # exe-path
alloy_run_args = f"run --disable-reporting=true --storage.path={tmp_dir} --server.http.memory-addr=alloy.internal:{alloy_debug_port} --server.http.listen-addr={alloy_interface}:{alloy_debug_port} {alloy_config_dir}"

alloy_subdirs=["config","scripts","files"]

script_exporter_config_std="std_script_exporter_config.yaml" # this is used for everything! need a std - or else will fail - in the std is a glob matching to *scripts_config.yaml
script_exporter_config = f"{alloy_config_rootdir}\\files\\std_script_exporter_config.yaml"
script_exporter_port = "10311"
script_exporter_interface = "127.0.0.1"
script_exporter_exe_path=f"{alloy_config_rootdir}\\script_exporter_amd64.exe"
script_exporter_args = f"-config.file {script_exporter_config} -web.listen-address {script_exporter_interface}:{script_exporter_port}" #change configpath to the right one
script_exporter_service_name="ScriptExporter"
updater_client_name = "AlloyUpdaterClient.exe"
sleep_in_s_startuptime = 5
##shawl service
shawl_exe_path = f"{alloy_config_rootdir}\\shawl_amd64.exe" # care check if \ is okay as path

updater_execution_intervall_in_m=5 #in prod 30! 
rand_delay_executing_s=10 # 10min

#new win
task_name = "AlloyUpdaterClient"
service_user="LocalSystem"

# LogRotate, also under win, cant get windowseventlog to work
log_max_size = 5 * 1024 * 1024  # 5 MB
log_backup_count = 2
log_max_age_days = 30 #not used! just max size
log_file_path = f"{alloy_config_rootdir}\\AlloyUpdaterClient.log"


#Versions patterns / update endpoint
alloy_version_pattern=r"version v([\d\.]+)"
alloy_version_opt="-v"
alloy_download_endpoint="/download/alloy_installer/amd64_exe"
script_exporter_version_pattern=r"version v([\d\.]+)"
script_exporter_version_opt="-version"
script_exporter_download_endpoint="/download/script_exporter/amd64_exe"
shawl_version_pattern=r"([\d\.]+)"
shawl_version_opt="-V"
shawl_download_endpoint="/download/shawl_service"


##crossplatform functions
def parseargs():
    parser = argparse.ArgumentParser(description='A great argparse function example.')
    parser.add_argument('-reinstall', '--reinstall', action='store_true', required=False, help='if set, deletes alloy and reinstalls it')
    parser.add_argument('-deinstall', '--deinstall', action='store_true', required=False, help='if set, deletes alloy')
    parser.add_argument('-install','--install', action='store_true', required=False, help='if set, installs the Updater-Client') # not used atm
    parser.add_argument('-dbg', '--debug', action='store_true', required=False, help='if set uses debug_dir where the script resides and logs debug')
    parser.add_argument('-nodelay', '--norandomdelay', action='store_true', required=False, help='if set, skips the random delay at the start')
    
    # Parsing arguments and returning
    return parser.parse_args()

def setup_structlog():
    global logger
    # Konfigurieren des Standard-Loggings
    handlers = [logging.StreamHandler()]

    if not args.deinstall and not args.reinstall:
        if not os.path.exists(os.path.dirname(log_file_path)):
            os.makedirs(os.path.dirname(log_file_path))
        handlers.append(logging.FileHandler(log_file_path))

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(message)s",
        handlers=handlers
    )
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            #structlog.dev.ConsoleRenderer(),
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.EventRenamer("msg"),
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


    logger=structlog.get_logger()

def setup_logger():
    global logger
    global requests_log
    # Logging konfigurieren
    if not os.path.exists(os.path.dirname(log_file_path)):
        os.makedirs(os.path.dirname(log_file_path))

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)  # Setze den Logger auf das höchste Level, um alle Nachrichten zu erfassen

    # File-Handler (Datei)
    if not args.deinstall and not args.reinstall:
        file_handler = logging.FileHandler(log_file_path)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        if args.debug:
            file_handler.setLevel(logging.DEBUG)
        else:
            file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)

    # Stream-Handler (Konsole)
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    if args.debug:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

def rotate_logfile(log_file, max_size, backup_count, max_age_days):
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
        # Logdatei erstellen
        open(log_file, 'a').close()
        logger.debug(f"Created {log_file}")

    if os.path.exists(log_file) and os.path.getsize(log_file) > max_size:
        # Rotieren der Logdatei
        for i in range(backup_count - 1, 0, -1):
            src = f"{log_file}.{i}"
            dst = f"{log_file}.{i + 1}"
            if os.path.exists(src):
                shutil.move(src, dst)
        shutil.move(log_file, f"{log_file}.1")
        if not os.path.exists(log_file):
            # Logdatei erstellen
            open(log_file, 'a').close()
            logger.debug(f"Created {log_file}")


    """# Löschen alter Backup-Dateien
    now = datetime.now()
    for i in range(1, backup_count + 1):
        backup_file = f"{log_file}.{i}"
        if os.path.exists(backup_file):
            file_mtime = datetime.fromtimestamp(os.path.getmtime(backup_file))
            if now - file_mtime > timedelta(days=max_age_days):
                os.remove(backup_file)"""

def fetch_server_versions():
    try:
        response = requests.post(f'{server_url}/check_updates', json={'hostname': hostname, 'operatingsystem': oprs,'need_signed_scripts': sign},verify=verify_ssl, auth=server_auth)

        response.raise_for_status()
        logger.debug(f"Server versions: {response.json()}")
        return response.json()
    except requests.exceptions.RequestException as e:
        try:
            logger.warning(response.text)
        except Exception:
            logger.warning(f"Error fetching server versions: {e}")
            return {}
        logger.warning(f"Error fetching server versions: {e}")
        return {}

def get_local_versions():
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
        root_dir=os.path.join(alloy_config_rootdir)
        add_empty_dirs(local_file_versions, root_dir)
        for root, _, files in os.walk(root_dir):
            for filename in files:
                filepath:str = os.path.join(root, filename) # the filenames gets appended maybe thats not working when dir is empty - cause some function needs the filename? but which
                if os.path.isfile(filepath):
                    """extract keys by path"""
                    path_list = filepath.split(os.sep)
                    folder=path_list[-2]
                    if root == root_dir:# Ignore files at the base level of the directory
                        continue
                    if "alloy-data" in path_list:# Ignore files in the "alloy-data" folder
                        continue
                    if filename==".env" or filename[:4]=="cus_":# Ignore all files named like "xxx"
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

def generate_file_hash(file_path, hash_algorithm='sha256'):
    hash_func = hashlib.new(hash_algorithm)
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def local_actions(file_changes)->bool: #returns if config changed
    def download_and_replace_file(path:str, alloy_config_rootdir,filename,oprs,hostname,sign)->None:
        try:
            # Hier wird angenommen, dass der Dateiname der letzte Teil des Pfades ist‚
            #filename = os.path.basename(path)
            #logger.debug(f"PATH: {path} Filename: {filename}")
            try:
                subfolder=path.split("/")[1] #- need "/" windows fix
                logger.debug(f"took subfolder[1]: on path={path}")
                logger.debug(f"took subfolder[1]={subfolder}")
                #print(f"d+r:SUBFOLDER NORMAL so: {subfolder} and file: {filename}")
            except IndexError:
                subfolder=path.split("/")[0] # this does only a half fix... idk - need "/" windows fix
                logger.debug(f"took on Indexerror: subfolder[0]: on path={path}")
                logger.debug(f"took on Indexerror: subfolder[0]={subfolder}")
                #print(f"d+r:SUBFOLDER GOT INDEXERROR so backup: {subfolder} and file: {filename}") #this isnt triggered :O
            # Erstellen Sie den vollständigen Pfad zur Datei
            file_path = os.path.join(alloy_config_rootdir,subfolder, filename)
            # URL zum Herunterladen der Datei
            url = f'{server_url}/download/files/{oprs}/{hostname}/{subfolder}/{sign}/{filename}'
            response = requests.get(url,verify=verify_ssl,auth=server_auth)
            response.raise_for_status()
            # Schreiben Sie den Inhalt in die Datei
            with open(file_path, 'wb') as file:
                file.write(response.content)
            logger.info(f"Downloaded and re/placed file: {file_path}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading file {filename}: {e}")
    
    def delete_local_file(path:str, alloy_config_rootdir,filename)->None:
        try:
            # Hier wird angenommen, dass der Dateiname der letzte Teil des Pfades ist
            try:
                subfolder=path.split("/")[1] #- need "/" windows fix
                logger.debug(f"took subfolder[1]: on path={path}")
                logger.debug(f"took subfolder[1]={subfolder}")
                #print(f"d+r:SUBFOLDER NORMAL so: {subfolder} and file: {filename}")
            except IndexError:
                subfolder=path.split("/")[0] # this does only a half fix... idk - need "/" windows fix
                logger.debug(f"took on Indexerror: subfolder[0]: on path={path}")
                logger.debug(f"took on Indexerror: subfolder[0]={subfolder}")
            #debug
            #print("DEL:SUBFOLDER",subfolder,"filename:",filename)
            # Erstellen Sie den vollständigen Pfad zur Datei
            file_path = os.path.join(alloy_config_rootdir,subfolder, filename)
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
                download_and_replace_file(path, alloy_config_rootdir,file,oprs,hostname,sign)
                reload_needed=True
        elif change['status'] == 'extra_in_local':
            for file in change['local_value']: # the trick is if local_value is empty the Loop gets executed 0 times so empty folders dont get deled
                delete_local_file(path, alloy_config_rootdir,file)
                #print("DETECT STRANGE VALUE OF file:",file)
                reload_needed=True
    if reload_needed:
        return True
    else:
        return False

def remove_empty_subdicts(mydict,subdict):
    keys_to_remove = [key for key, value in mydict.items() if subdict in value and value[subdict] == {}]
    for key in keys_to_remove:
        del mydict[key]

##windows specials
def create_scheduled_task_copy_updater(): #creates Task if didnt exists
    task_command = f'{alloy_config_rootdir}\\{updater_client_name}'

    # Command to check if the scheduled task exists
    schtasks_query_command = ['schtasks', '/Query', '/TN', task_name]

    try:
        # Check if the task already exists
        subprocess.run(schtasks_query_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"Scheduled task '{task_name}' already exists.")
    except subprocess.CalledProcessError:
        # Task does not exist, create it
        schtasks_create_command = [
            'schtasks', '/Create', '/SC', 'MINUTE', '/MO', f'{updater_execution_intervall_in_m}', '/TN', task_name,
            '/TR', f'"{task_command}"', '/RU', 'SYSTEM', '/F'
        ]
        try:
            subprocess.run(schtasks_create_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info(f"Scheduled task '{task_name}' created successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create scheduled task '{task_name}'. Error: {e}")

def remove_scheduled_task():
    schtasks_delete_command = ['schtasks', '/Delete', '/TN', task_name, '/F']
    try:
        subprocess.run(schtasks_delete_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Scheduled task '{task_name}' deleted successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to delete scheduled task '{task_name}'. Error: {e}")

def install_windows_service_shawl(service_name,exe_path,exe_args):
    try:
        query_service_command = ['sc.exe', 'create', service_name, 'binPath=', f'{shawl_exe_path} run --name {service_name} -- {exe_path} {exe_args}']
        result = subprocess.run(query_service_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(sleep_in_s_startuptime) #sleep after install to give time for service up
    except subprocess.CalledProcessError:
        logger.error(f"Service '{service_name}' creation failed with {result.stdout.rstrip()} {result.stderr.rstrip()}!.")

def check_and_start_service(service_name:str,interface,port):
    """
    Überprüft, ob der Dienst bereits erstellt wurde und ob er gestartet ist. Startet den Dienst, falls er nicht läuft.
    Returns True if Service is started and really serving

    :param service_name: Der interne Name des Dienstes.
    """
    started=False
    try:
        # Befehl zum Überprüfen des Dienststatus
        query_service_command = ['sc.exe', 'query', service_name]
        result = subprocess.run(query_service_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Überprüfen, ob der Dienst läuft
        if b"RUNNING" not in result.stdout:
            logger.info(f"Service '{service_name}' is not running. Attempting to start it.")
            start_service_command = ['sc.exe', 'start', service_name]
            subprocess.run(start_service_command, check=True, timeout=3, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info(f"Service '{service_name}' started successfully - sleeping for {sleep_in_s_startuptime} to check.")
            time.sleep(sleep_in_s_startuptime)
            started=True
        else:
            logger.debug(f"Service '{service_name}' is already running.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to query or start service '{service_name}'. Error: {e}")
    except subprocess.TimeoutExpired as e:
        logger.error(f"Timeout while starting service '{service_name}' ")
    try: #special 
        response=requests.get(f"http://{interface}:{port}")
        response.raise_for_status()
        logger.info(f"{service_name} http is serving")
        if started:
            return True
    except requests.exceptions.ConnectionError:
        logger.error(f"{service_name} http connection error")
    except Exception as e:
        logger.error(f"{service_name} unkown error trying to reach http error: {e}")
    
def check_service_install_running(service_name,exe_path,exe_args,interface,port):
    try:
        query_service_command = ['sc.exe', 'query', service_name]
        result = subprocess.run(query_service_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"Service '{service_name}' already exists.")
    except subprocess.CalledProcessError:
        logger.info(f"Service '{service_name}' does not exist. Installing service.")
        install_windows_service_shawl(service_name, exe_path, exe_args)
    started=check_and_start_service(service_name,interface,port)
    if started:
        return started

def uninstall_windows_service(service_name):
    try:
        query_service_command = ['sc.exe', 'query', service_name]
        result = subprocess.run(query_service_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Service '{service_name}' exists, continuing deinstall.")
        try:
            query_service_command = ['sc.exe', 'stop', service_name]
            result = subprocess.run(query_service_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logger.warning(f"Service '{service_name}' stopping failed with {result.stdout.rstrip()} {result.stderr.rstrip()} !.")
        try:
            query_service_command = ['sc.exe', 'delete', service_name]
            result = subprocess.run(query_service_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logger.warning(f"Service '{service_name}' deletion failed!.")
    except subprocess.CalledProcessError:
        logger.warning(f"Service '{service_name}' does not exist. Skipping deinstall.")

def check_and_create_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
        logger.info(f"Verzeichnis erstellt: {directory}")
    else:
        logger.debug(f"Verzeichnis existiert bereits: {directory}")

def pre_install_setup_dir_permissions():
    #check if dirs are there and permissions are right, if not set/create them
    def set_permissions_ps(directory):
            # PowerShell-Skript als String definieren
        ps_script = f"""
        $sm_path = '{directory}'
        $sm_path_acls = Get-Acl -Path $sm_path
        $sm_path_acls.SetAccessRuleProtection($true, $false)
        
        # SYSTEM
        $identity = "SYSTEM"
        $fsAcRArgs = $identity, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
        $fsAcR = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fsAcRArgs
        $sm_path_acls.SetAccessRule($fsAcR)

        # Administrators
        $identity = "Administrators"
        $fsAcRArgs = $identity, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
        $fsAcR = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fsAcRArgs
        $sm_path_acls.SetAccessRule($fsAcR)
                    
        Set-Acl -Path $sm_path -AclObject $sm_path_acls
        """

        # PowerShell-Skript ausführen
        result = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.debug(f"Berechtigungen für {directory} erfolgreich gesetzt.")
        else:
            logger.error(f"Fehler beim Setzen der Berechtigungen für {directory}: {result.stderr}")

    #Create dir and subdirs
    check_and_create_dir(alloy_config_rootdir)
    for sub_dir in alloy_subdirs:
        check_and_create_dir(os.path.join(alloy_config_rootdir,sub_dir))
    #set permissions
    #set_permissions(alloy_config_rootdir)
    set_permissions_ps(alloy_config_rootdir)
    for sub_dir in alloy_subdirs:
        #set_permissions(os.path.join(alloy_config_rootdir,sub_dir))
        set_permissions_ps(os.path.join(alloy_config_rootdir,sub_dir))
    
def after_uninstall_remove_dir():
    def check_and_delete_dir(directory):
        if os.path.exists(directory):
            shutil.rmtree(directory)
            logger.info(f"Verzeichnis und alle Inhalte gelöscht: {directory}")
        else:
            logger.info(f"Verzeichnis existiert nicht: {directory}")
    check_and_delete_dir(alloy_config_rootdir)
    for sub_dir in alloy_subdirs:
        check_and_delete_dir(os.path.join(alloy_config_rootdir, sub_dir))

def reload_alloy_configcheck(restart=False):
    restarted=False
    try:
        response = requests.get(f'http://{alloy_interface}:{alloy_debug_port}/-/reload')
        response.raise_for_status()
        if response.text.strip() != "config reloaded":
            logger.debug(f"Failed reloading alloy service with http:\n {response.text}")
        else:
            logger.info(f"Alloy: {response.text}")
        #do something if the response is config reload failed config fault
    except Exception as e:
        logger.debug(f"Failed reloading alloy service with http {repr(e)} ...trying to restart service")
        try:
            logger.warning(f"Alloy config error: {response.text}")
            if response.status_code==400:
                logger.debug(f"Im not reloading the service, config seems broken!")
                return False
        except UnboundLocalError:
            pass
        service_restart(alloy_service_name,alloy_interface,alloy_debug_port)
        restarted=True
    if restart and not restarted:
        service_restart(alloy_service_name,alloy_interface,alloy_debug_port)

def script_exporter_configcheck()->bool:# Script Exporter can have a subconfig file that can be matched with glob! and doesnt need to exist!!!
    try:
        command=[script_exporter_exe_path,"-config.check","-config.file", script_exporter_config]
        result=subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"Script_Exporter config valid {result.stdout.rstrip()} {result.stderr.rstrip()}")
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"Script_Exporter config not valid or could not check {e} {result.stdout.rstrip()} {result.stderr.rstrip()}")
        return False
    except Exception as e:
        logger.error(f"Script_Exporter configcheck failed with unkown Error {e} {result.stdout.rstrip()} {result.stderr.rstrip()}")
        return False

def script_exporter_restart_flow():
    success=script_exporter_configcheck()
    if success:
        started=service_restart(script_exporter_service_name,script_exporter_interface,script_exporter_port,sleep_in_s_startuptime)
        if started:
            logger.info(f"Script_Exporter restarted")
        else:
            logger.error(f"Script_Exporter not re/started")
    else:
        logger.warning(f"Script_Exporter not restartet, cause configcheck failed")

def check_http_serving(service_name,interface,port):
    try:
        response = requests.get(f'http://{interface}:{port}')
        response.raise_for_status()
    except Exception as e:
        logger.error(f"{service_name} not reachable after restarting giving up... , {e}")

def service_restart(service_name,interface,port,sleep_between_stop_start=2): 
    try:
        command=["sc.exe","stop", service_name]
        result=subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"{service_name} stopped in order to start again {result.stdout.rstrip()} {result.stderr.rstrip()}")
    except subprocess.CalledProcessError as e:
        logger.debug(f"{service_name} failed to stopp.. {result.stdout.rstrip()} {result.stderr.rstrip()}")
    time.sleep(sleep_between_stop_start)
    logger.debug(f"Waited for {sleep_between_stop_start} to start {service_name} again")
    try:
        command=["sc.exe","start", service_name]
        result=subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"Started {service_name} Service again {result.stdout.rstrip()} {result.stderr.rstrip()}")
        started=True
    except subprocess.CalledProcessError as e:
        logger.debug(f"{service_name} failed to start.. {result.stdout.rstrip()} {result.stderr.rstrip()}")
    time.sleep(sleep_in_s_startuptime)
    try:
        response = requests.get(f'http://{interface}:{port}')
        response.raise_for_status()
        if started:
            return True
    except Exception as e:
        logger.error(f"{service_name} not reachable after restarting giving up... waited {sleep_between_stop_start}, {e}")

def check_fetch_exe_versions(): #updater function
    def is_version_greater(version1: str, version2: str):
        def parse_version(version: str):
            return list(map(int, version.split('.')))
        return parse_version(version1) > parse_version(version2)
    def is_version_lower(version1: str, version2: str):
        def parse_version(version: str):
            return list(map(int, version.split('.')))
        return parse_version(version1) < parse_version(version2)
    def generic_check_local_exe_version(exe_path,version_cmd,pattern):
        try:
            command=[exe_path,version_cmd]
            result=subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
            version_pattern = pattern
            match = re.search(version_pattern, result.stdout)
            if match:
                version_number = match.group(1)
                logger.debug(f"Local {exe_path} Version: {version_number}")
                return version_number
            else:
                logger.error(f"Local {exe_path} Version not found {result.stdout.rstrip()} {result.stderr.rstrip()}.")
        except subprocess.CalledProcessError as e:
            if os.path.isfile(exe_path):
                logger.error(f"Failed to {exe_path} {version_cmd} but file exists : {result.stdout.rstrip()} {result.stderr.rstrip()}...")
            else:
                return False
        except FileNotFoundError as e:
            return False

    try:
        response = requests.get(f'{server_url}/check_rpm_updates/{build_type}',verify=verify_ssl,auth=server_auth)
        response.raise_for_status()
        server_versions=response.json()
        logger.debug(f"Serverversions: {server_versions}")
        local_versions={}
        #maybe move the pattern and endpoints to global vars! :) # i did it #TODO Test
        local_versions["alloy"]={"version":generic_check_local_exe_version(alloy_exe_path,alloy_version_opt,alloy_version_pattern),"endpoint":alloy_download_endpoint}
        local_versions["script_exporter"]={"version":generic_check_local_exe_version(script_exporter_exe_path,script_exporter_version_opt,script_exporter_version_pattern),"endpoint":script_exporter_download_endpoint}
        local_versions["shawl"]={"version":generic_check_local_exe_version(shawl_exe_path,shawl_version_opt,shawl_version_pattern),"endpoint":shawl_download_endpoint}
        update={}
        for key,local_version in local_versions.items():
            if local_version["version"]==False:#trigger to download regardless of status! exp. if not installed :)
                logger.info(f"{key} not found ... downloading")
                #download_file(local_version["endpoint"])
                update[key]={"download":True}
                update[key]["endpoint"]=local_version["endpoint"]
            elif local_version["version"] and is_version_greater(server_versions[key], local_version["version"]):
                logger.info(f"{key} local: {local_version['version']} remote:{server_versions[key]} newer Version available  ... upgrading")
                #download_file(local_version["endpoint"])
                update[key]={"download":True}
                update[key]["endpoint"]=local_version["endpoint"]
            elif local_version["version"] and is_version_lower(server_versions[key], local_version["version"]):
                logger.info(f"{key} local: {local_version['version']} remote:{server_versions[key]} older Version available ... downgrading")
                #download_file(local_version["endpoint"])
                update[key]={"download":True}
                update[key]["endpoint"]=local_version["endpoint"]
            elif local_version["version"]:
                logger.debug(f"{key} local: {local_version['version']} remote:{server_versions[key]} in sync with server")
                update[key]={"download":False}
            else:
                update[key]={"download":None}#Nothing failed to get version but file exists, big error :() - but already logged - maybe handle with redownload - dont know yet - could trigger a redownload on fails every time...
        
        services_with_download_false = [service for service, details in update.items() if details.get("download") is False]
        logger.info(f"App Versions in Sync with Remote: {len(services_with_download_false)} [{', '.join(services_with_download_false)}]")

        alloy_rdy=None
        script_exporter_rdy=None
        shawl_path=None
        alloy_path=None
        script_exporter_path=None
        if update["shawl"]["download"]:
            logger.debug("Preparing shawl download")
            if check_service_exists(alloy_service_name)==True:
                if check_service_running(alloy_service_name)==True:
                    if stop_service(alloy_service_name)==True:
                        alloy_rdy=True
                elif check_service_running(alloy_service_name)==False:
                    alloy_rdy=True
            elif check_service_exists(alloy_service_name)==False:
                alloy_rdy=True
            if check_service_exists(script_exporter_service_name)==True:
                if check_service_running(script_exporter_service_name)==True:
                    if stop_service(script_exporter_service_name)==True:
                        script_exporter_rdy=True
                elif check_service_running(script_exporter_service_name)==False:
                    script_exporter_rdy=True
            elif check_service_exists(script_exporter_service_name)==False:
                script_exporter_rdy=True
            if alloy_rdy and script_exporter_rdy:
                shawl_path=download_file_new(local_versions["shawl"]["endpoint"])
            else:
                logger.warning("Up/Downgrading shawl not started, alloy and/or scriptexporter not rdy") 

        if update["alloy"]["download"]:
            logger.debug("Preparing alloy download")
            if not alloy_rdy:
                if check_service_exists(alloy_service_name)==True:
                    if check_service_running(alloy_service_name)==True:
                        if stop_service(alloy_service_name)==True:
                            alloy_rdy=True
                    elif check_service_running(alloy_service_name)==False:
                        alloy_rdy=True
                elif check_service_exists(alloy_service_name)==False:
                    alloy_rdy=True
            if alloy_rdy:
                alloy_path=download_file_new(local_versions["alloy"]["endpoint"]) 
            else:
                logger.warning("Up/Downgrading Alloy not started, alloy not rdy") 

        if update["script_exporter"]["download"]:
            logger.debug("Preparing alloy download")
            if not script_exporter_rdy:
                if check_service_exists(script_exporter_service_name)==True:
                    if check_service_running(script_exporter_service_name)==True:
                        if stop_service(script_exporter_service_name)==True:
                            script_exporter_rdy=True
                    elif check_service_running(script_exporter_service_name)==False:
                        script_exporter_rdy=True
                elif check_service_exists(script_exporter_service_name)==False:
                    script_exporter_rdy=True
            if script_exporter_rdy:
                script_exporter_path=download_file_new(local_versions["script_exporter"]["endpoint"]) 
            else:
                logger.warning("Up/Downgrading Script_Exporter not started, alloy not rdy") 

        logger.debug(f"{update}") 
        return alloy_path,script_exporter_path,shawl_path
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching server rpmversions: {e} ... skipping updates")

def check_service_running(service_name):
    try:
        # Befehl zum Überprüfen des Dienststatus
        query_service_command = ['sc.exe', 'query', service_name]
        result = subprocess.run(query_service_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Überprüfen, ob der Dienst läuft
        if b"RUNNING" not in result.stdout:
            logger.debug(f"Service '{service_name}' is not running.")
            return False
        else:
            logger.debug(f"Service '{service_name}' is running.")
            return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to query service '{service_name}'. Error: {e}")
    except subprocess.TimeoutExpired as e:
        logger.error(f"Timeout while query on service '{service_name}' ")

def stop_service(service_name):
    try:
        command=["sc.exe","stop", service_name]
        result=subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"{service_name} stopped")
        return True
    except subprocess.CalledProcessError as e:
        logger.debug(f"{service_name} failed to stopp.. {result.stdout.rstrip()} {result.stderr.rstrip()}")
        return False

def download_file_new(endpoint):
    if not os.path.exists(alloy_config_rootdir):
        logger.error(f"{alloy_config_rootdir} does not exist")
        return False
    try:
        with requests.get(f"{server_url}{endpoint}", stream=True,verify=verify_ssl,auth=server_auth) as r:
            r.raise_for_status()
            content_disposition = r.headers.get('content-disposition')
            if content_disposition:
                filename = content_disposition.split('filename=')[1].strip('"')
                logger.debug(f"filename={filename}")
            else:
                logger.error("Possible Server Error, no filename in response")
                return False
            local_filename = os.path.join(alloy_config_rootdir, filename)
            temp_filename = local_filename + ".part"
            try:
                with open(temp_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                os.replace(temp_filename, f"{local_filename}")
            except Exception as e:
                logger.error(f"Error while writing file: {e}")
                try:
                    if os.path.exists(temp_filename):
                        os.remove(temp_filename)
                except OSError as delete_error:
                    logger.error(f"Error while deleting temporary file: {delete_error}")
                return False
    except requests.RequestException as e:
        logger.error(f"Error while downloading file: {e}")
        return False

    return local_filename

def check_service_exists(service_name):
    try:
        query_service_command = ['sc.exe', 'query', service_name]
        result = subprocess.run(query_service_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(f"Service '{service_name}' already exists.")
        return True
    except subprocess.CalledProcessError:
        logger.debug(f"Service '{service_name}' does not exists.")
        return False

def log_uncaught_exceptions(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    # Extrahieren des Ausnahmetyps und der Stelle, an der die Ausnahme aufgetreten ist
    tb = traceback.extract_tb(exc_traceback)
    if tb:
        last_frame = tb[-1]
        filename = last_frame.filename
        lineno = last_frame.lineno
        funcname = last_frame.name
        exception_info = f"{exc_type.__name__} in {filename} at line {lineno}, in {funcname}"
    else:
        exception_info = f"{exc_type.__name__}"

    logger.error("Uncaught exception", exception_info=exception_info)
    sys.exit(1)

def set_service_to_automatic(service_name):
    try:
        # Befehl zum Setzen des Dienstes auf "Automatisch" mit sc.exe
        command = f'sc.exe config "{service_name}" start= auto'
        # Ausführen des Befehls
        subprocess.run(command, check=True, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug(f"Der Dienst '{service_name}' wurde auf 'Automatisch' gesetzt.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Fehler beim Setzen des Dienstes '{service_name}' auf 'Automatisch': {e}")

def main():
    global args
    args = parseargs()
    #setup_logger()
    setup_structlog()
    # Setzen des globalen Ausnahmehandlers
    if not args.debug:
        sys.excepthook = log_uncaught_exceptions
    #logger.error("TestError")
    logger.debug("Running...")
    if args.norandomdelay or args.reinstall or args.deinstall or args.install: #Normally Script waits for rand intervall if norandomdelay is passed, skipping
        random_delay = 0
    else:
        random_delay = random.randint(0, rand_delay_executing_s)
        logger.debug(f"Waiting {random_delay}s... pass -nodelay for no waiting")
        time.sleep(random_delay)
    #Getting Special Vars
    fqhn=socket.getfqdn()
    logger.debug(f"fqhn={fqhn}")

    global hostname
    global sign
    global oprs
    hostname=fqhn.split(".")[0]
    logger.debug(f"Hostname: {hostname}")
    if fqhn.split(".")[-1]=="de":#TODO Test
        sign=True
        logger.debug(f"Need sign: {sign}")
    else:
        sign=False
        logger.debug(f"Need sign: {sign}")
    oprs="win"

    #MAIN LOGIC start
    if args.deinstall or args.reinstall:
        remove_scheduled_task() 
        uninstall_windows_service(alloy_service_name)#deinstall
        uninstall_windows_service(script_exporter_service_name)#deinstall
        after_uninstall_remove_dir()#remove dir tree
        if not args.reinstall:#deinstall only - or not exiting leading to new intall
            logger.debug("Deinstall done .. exiting")
            sys.exit(0) #Exit after deinstalling

    pre_install_setup_dir_permissions()
    remote_files=fetch_server_versions()

    if remote_files:
        local_files=get_local_versions()
        file_changes=compare_dicts(local_files,remote_files)
        # Entfernen von Einträgen mit leerem local_value # this works
        keys_to_remove = [key for key, value in file_changes.items() if 'local_value' in value and value['local_value'] == {}]
        for key in keys_to_remove:
            del file_changes[key]
        if file_changes:
            logger.info(f"Remote_dir: changes: {file_changes}")
        else:
            logger.info("Remote_dir: no changes")
        config_changed=local_actions(file_changes)
    else:
        logger.warning("got no remote_files skipping next steps")
        #i think the error is big enough to stop the script! Thats true!
        sys.exit(1)

    #TODO Thew following Flow could be better, with less duplicate checks 
    alloy_new,script_exporter_new,shawl_new=check_fetch_exe_versions()
    #=check_fetch_exe_versions()

    started_alloy=check_service_install_running(alloy_service_name,alloy_exe_path,alloy_run_args,alloy_interface,alloy_debug_port) #TODO return not used?!
    started_script_exporter=check_service_install_running(script_exporter_service_name,script_exporter_exe_path,script_exporter_args,script_exporter_interface,script_exporter_port)#TODO return not used?!

    if config_changed:
        reload_alloy_configcheck() 
        script_exporter_restart_flow()
    
    #started_alloy=check_service_install_running(alloy_service_name,alloy_exe_path,alloy_run_args,alloy_interface,alloy_debug_port)
    #started_script_exporter=check_service_install_running(script_exporter_service_name,script_exporter_exe_path,script_exporter_args,script_exporter_interface,script_exporter_port)

    #TODO flow could be better till here - rest is good
    set_service_to_automatic(alloy_service_name)
    set_service_to_automatic(script_exporter_service_name)

    if args.install: #updater task here? or integrate in normal flow?
        create_scheduled_task_copy_updater()
        pass #dont install task now while debugging, only if really build or it will fail :)

    logger.debug("Done...")
    if not args.deinstall and not args.reinstall:
        rotate_logfile(log_file_path,log_max_size,log_backup_count,log_max_age_days)

if __name__=="__main__":
    main()
