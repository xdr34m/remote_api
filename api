from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import asyncio
from contextlib import asynccontextmanager
import logging
import signal
import glob
import hashlib
import sys
from fastapi.middleware.gzip import GZipMiddleware
import json
import redis

redis_host=os.getenv("REDIS_HOST")
redis_port=os.getenv("REDIS_PORT")
# Redis-Verbindung
redis_client = redis.Redis(host=redis_host, port=redis_port, db=0)

#TODO Make sure its okay for FW to reach this API Server !!! like Telegraf
# Configure logging
#logging.basicConfig(level=logging.INFO)
#logger = logging.getLogger(__name__)
# Configure logging to stderr
logger=logging.getLogger('my_logger')
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logging.info("Starting up...")
app = FastAPI(root_path="/rdir/api")
app.add_middleware(GZipMiddleware, minimum_size=1000)  # Aktiviert GZip-Komprimierung für Antworten größer als 1000 Bytes aka files # tested and works!
 
# Directory to monitor
directory_to_watch = '../testserverpath'
#Hostname dir depth
os_dir_depth=2
hostname_dir_depth=3
folder_dir_depth=4
default_dirnames=["DEFAULT","DEFAULT_signed","DEFAULT_unsigned"]
std_dirnames=["STD","STD_signed","STD_unsigned"]
#some vars
default_file='default.alloy'
rpm_pattern='alloy*.rpm'
win_initial_install_path='../client/alloy_updater_client_win.exe' # member needs exe to be build from py for prod
rhel_initial_install_path='../client/alloy_updater_client_rhel' # member needs exe to be build from py for prod - care - this is build on rhel 8 not on 7
alloy_build_path_woFilename='../alloy_builds/'
script_exporter_build_path_woFilename="../scriptexporter_builds/"
shawl_service_build_path_woFilename="../shawl_builds/"

# Dictionary to hold file versions for each host
file_versions = []
special_versions = []
file_hashes = {}
rpm_version='XXX' # should i really check for higher versions? or just set a marker that the host hast to upgrade on next check - with a specific rpm

class FileData(BaseModel):
    hostname: str
    operatingsystem: str
    need_signed_scripts: bool | None = None

@app.get('/ready') #Healthcheck
async def receive_healthcheck():
    return "ready"

@app.post('/check_updates') # Returns Json with hashes to all files in the dirs
async def check_updates(file_data: FileData):
    def add_nested_key(dictionary, keys, value):
        sub_dict = dictionary
        for key in keys[:-1]:
            if key not in sub_dict:
                sub_dict[key] = {}
            sub_dict = sub_dict[key]
        sub_dict[keys[-1]] = value

    def has_key_value_pairs(data, keys):
        sub_dict = data
        for key in keys:
            if key not in sub_dict:
                return False
            sub_dict = sub_dict[key]
        return bool(sub_dict)
    
    # Abrufen der Dateiversionen aus Redis
    file_versions = json.loads(redis_client.get('file_versions') or '[]')
    special_versions = json.loads(redis_client.get('special_versions') or '[]')
    
    returndict = {}
    # Suche nach dem entsprechenden Dictionary basierend auf dem hostname
    returndict = next((item for item in file_versions if item.get("hostname") == file_data.hostname), {})
    logging.debug(returndict)
    
    # Check os mismatch
    if returndict and file_data.operatingsystem != returndict["os"]:
        logging.error(f"operatingsystem_mismatch client reported {file_data.operatingsystem} but returndict has {returndict['os']} - please check client/server config")
        raise HTTPException(status_code=404, detail='operatingsystem_mismatch - please check client/server config')

    # Operating system switch
    if file_data.operatingsystem == "win":  # Check which OS    
        if file_data.need_signed_scripts:
            try:
                special_dir_dict = next((item for item in special_versions if item.get("special_dir") == "DEFAULT_signed" and item.get("os") == file_data.operatingsystem), {})
                for subfolder in ["files", "scripts", "config"]:
                    if not has_key_value_pairs(returndict, ['dirs', subfolder]):
                        for itemkey, itemvalue in special_dir_dict.get(subfolder, {}).items():
                            add_nested_key(returndict, ["dirs", subfolder, itemkey], itemvalue)
            except KeyError as e:
                logging.info(f"KeyError searching DEFAULT_signed {repr(e)}")
        elif file_data.need_signed_scripts == False:
            try:
                special_dir_dict = next((item for item in special_versions if item.get("special_dir") == "DEFAULT_unsigned" and item.get("os") == file_data.operatingsystem), {})
                for subfolder in ["files", "scripts", "config"]:
                    if not has_key_value_pairs(returndict, ['dirs', subfolder]):
                        for itemkey, itemvalue in special_dir_dict.get(subfolder, {}).items():
                            add_nested_key(returndict, ["dirs", subfolder, itemkey], itemvalue)
            except KeyError as e:
                logging.info(f"KeyError searching DEFAULT_unsigned {repr(e)}")

        if file_data.need_signed_scripts:
            try:
                special_dir_dict = next((item for item in special_versions if item.get("special_dir") == "STD_signed" and item.get("os") == file_data.operatingsystem), {})
                for subfolder in ["files", "scripts", "config"]:
                    for itemkey, itemvalue in special_dir_dict.get(subfolder, {}).items():
                        add_nested_key(returndict, ["dirs", subfolder, itemkey], itemvalue)
            except KeyError as e:
                logging.info(f"KeyError searching STD_signed {repr(e)}")
        elif file_data.need_signed_scripts == False:
            try:
                special_dir_dict = next((item for item in special_versions if item.get("special_dir") == "STD_unsigned" and item.get("os") == file_data.operatingsystem), {})
                for subfolder in ["files", "scripts", "config"]:
                    for itemkey, itemvalue in special_dir_dict.get(subfolder, {}).items():
                        add_nested_key(returndict, ["dirs", subfolder, itemkey], itemvalue)
            except KeyError:
                logging.info("KeyError searching STD_unsigned")
        else:
            logging.error(f"failed to determine if signed or unsigned scripts")

    elif file_data.operatingsystem == "rhel":
        special_dir_dict = next((item for item in special_versions if item.get("special_dir") == "DEFAULT" and item.get("os") == file_data.operatingsystem), {})
        for subfolder in ["files", "scripts", "config"]:
            if not has_key_value_pairs(returndict, ['dirs', subfolder]):
                for itemkey, itemvalue in special_dir_dict.get(subfolder, {}).items():
                    add_nested_key(returndict, ["dirs", subfolder, itemkey], itemvalue)
        try:
            special_dir_dict = next((item for item in special_versions if item.get("special_dir") == "STD" and item.get("os") == file_data.operatingsystem), {})
            for subfolder in ["files", "scripts", "config"]:
                for itemkey, itemvalue in special_dir_dict.get(subfolder, {}).items():
                    add_nested_key(returndict, ["dirs", subfolder, itemkey], itemvalue)
        except KeyError:
            logging.info("KeyError searching STD")
    else:
        raise HTTPException(status_code=404, detail="Operating System not correctly set")
    if returndict==[]:
        logger.error("returndict of check_updates is empty, check redis!")
        raise HTTPException(status_code=405, detail="Redis seems empty! Error!")
    else:
        return returndict

@app.get('/download/files/{oprs}/{hostname}/{folder}/{signed}/{filename}')#main download endpoint! for everything config/files related
async def download_file(oprs:str, hostname: str, folder: str, signed: str,filename: str):
    if filename[:4]=="std_":
        if oprs=="win":
            if signed.lower()=="true":
                build_path=f"{oprs}/STD_signed/{folder}/{filename}"
            elif signed.lower()=="false":
                build_path=f"{oprs}/STD_unsigned/{folder}/{filename}"
            else:
                raise HTTPException(status_code=404, detail='signed parameter not correct')
        elif oprs=="rhel":
            build_path=f"{oprs}/STD/{folder}/{filename}"
        else:
            raise HTTPException(status_code=404, detail=f'OS not supported {oprs}')
    elif filename[:8]=="default_":
        logger.debug("triggered default elif")
        if oprs=="win":
            if signed.lower()=="true":
                build_path=f"{oprs}/DEFAULT_signed/{folder}/{filename}"
            elif signed.lower()=="false":
                build_path=f"{oprs}/DEFAULT_unsigned/{folder}/{filename}"
            else:
                raise HTTPException(status_code=404, detail='signed parameter not correct')
        elif oprs=="rhel":
            build_path=f"{oprs}/DEFAULT/{folder}/{filename}"
        else:
            raise HTTPException(status_code=404, detail=f'OS not supported {oprs}')
        logger.debug(build_path)
    else:
        build_path=f"{oprs}/{hostname}/{folder}/{filename}"
    fullpath=os.path.join(directory_to_watch,build_path)
    logging.debug(f"File requested={fullpath}")
    #debug
    #with open(fullpath,'r') as f:
    #    content=f.read()
    #logging.debug(f"File Content={content}")    
    
    return FileResponse(fullpath,filename=filename)

@app.get('/download/initial_install/{oprs}/{update}')#sec download endpoint for initial installscripts # i think not needed - everything in the alloy_updater!
async def download_init_install(oprs:str,update:bool):
    filename="alloy_updater_client"
    if oprs=="win":
        return FileResponse(win_initial_install_path,filename=filename)
    elif oprs=="rhel":
        return FileResponse(rhel_initial_install_path,filename=filename)
    else:
        raise HTTPException(status_code=404, detail=f"Operating System not correctly set / not featured {oprs}")

@app.get('/check_rpm_updates/{build_type}')
async def check_rpm_updates(build_type: str):
    """
    Returnes
    """
    """file_paths=[]
    for root, _, files in os.walk(alloy_build_path_woFilename):
        for file in files:
            file_paths.append(os.path.join(root, file))"""
    def return_first_file_matching_buildtype_in_dir(folder):
        file_paths = [os.path.join(folder, file) for file in os.listdir(folder) if os.path.isfile(os.path.join(folder, file))]
        filepath=""
        if build_type=="amd64_exe":
            for path in file_paths:
                if path.endswith('amd64.exe'):
                    filepath=path
                    break
        elif build_type=="amd64_rpm":
            for path in file_paths:
                if path.endswith('.amd64.rpm'):
                    filepath=path
                    break
        else:
            raise HTTPException(status_code=404, detail=f"{build_type} build type not featured")
        try:
            filename=filepath.split(os.path.sep)[-1]
            version=filename.split("-")[1]
            return version
        except IndexError:
            logger.error(f"no file found for {build_type} in {filepath}")
            raise HTTPException(status_code=499, detail=f"{build_type} no build found")
        
    if build_type=="amd64_exe":
        alloy_version=return_first_file_matching_buildtype_in_dir(alloy_build_path_woFilename)
        script_exporter_version=return_first_file_matching_buildtype_in_dir(script_exporter_build_path_woFilename)
        shawl_version=return_first_file_matching_buildtype_in_dir(shawl_service_build_path_woFilename)
        return {"alloy":alloy_version,"script_exporter":script_exporter_version,"shawl":shawl_version}
        
    elif build_type=="amd64_rpm":
        alloy_version=return_first_file_matching_buildtype_in_dir(alloy_build_path_woFilename)
        script_exporter_version=return_first_file_matching_buildtype_in_dir(script_exporter_build_path_woFilename)
        return {"alloy":alloy_version,"script_exporter":script_exporter_version}

@app.get('/download/alloy_installer/{build_type}')
async def download_alloy_installer(build_type:str):
    """
    Care directly returns first matched file!
    """
    """file_paths=[]
    for root, _, files in os.walk(alloy_build_path_woFilename):
        for file in files:
            file_paths.append(os.path.join(root, file))"""
    file_paths = [os.path.join(alloy_build_path_woFilename, file) for file in os.listdir(alloy_build_path_woFilename) if os.path.isfile(os.path.join(alloy_build_path_woFilename, file))]
    filepath=""
    if build_type=="amd64_exe":
        for path in file_paths:
            if path.endswith('amd64.exe'):
                filepath=path
                filename=filepath.split(os.path.sep)[-1]
                filename_list=filename.split("-")
                filename=f"{filename_list[0]}_{filename_list[3]}"
                break
    elif build_type=="amd64_rpm":
        for path in file_paths:
            if path.endswith('.amd64.rpm'):
                filepath=path
                filename=filepath.split(os.path.sep)[-1]
                break
    else:
        raise HTTPException(status_code=404, detail=f"{build_type} build type not featured")
    logger.debug(f"{path},{filepath.split(os.path.sep)[-1]}")
    if not filepath:
        raise HTTPException(status_code=499, detail=f"Alloy: No file found for build type {build_type}")
    return FileResponse(path,filename=filename)

@app.get('/download/script_exporter/{build_type}')
async def download_script_exporter_installer(build_type:str):
    file_paths = [os.path.join(script_exporter_build_path_woFilename, file) for file in os.listdir(script_exporter_build_path_woFilename) if os.path.isfile(os.path.join(script_exporter_build_path_woFilename, file))]
    filepath=""
    if build_type=="amd64_exe":
        for path in file_paths:
            if path.endswith('amd64.exe'):
                filepath=path
                filename=filepath.split(os.path.sep)[-1]
                filename_list=filename.split("-")
                filename=f"{filename_list[0]}_{filename_list[2]}"
                break
    elif build_type=="amd64_rpm":
        for path in file_paths:
            if path.endswith('amd64.rpm'):
                filepath=path
                filename=filepath.split(os.path.sep)[-1]
                break
    else:
        raise HTTPException(status_code=404, detail=f"{build_type} build type not featured")
    logger.debug(f"{path},{filepath.split(os.path.sep)[-1]}")
    if not filepath:
        raise HTTPException(status_code=499, detail=f"Script_Exporter: No file found for build type {build_type}")
    return FileResponse(path,filename=filename)

@app.get('/download/shawl_service')
async def download_shawl_service():
    file_paths = [os.path.join(shawl_service_build_path_woFilename, file) for file in os.listdir(shawl_service_build_path_woFilename) if os.path.isfile(os.path.join(shawl_service_build_path_woFilename, file))]
    for path in file_paths:
        if path.endswith('amd64.exe'):
            filepath=path
            filename=filepath.split(os.path.sep)[-1]
            filename_list=filename.split("-")
            filename_wo_version=f"{filename_list[0]}_{filename_list[2]}"
            break
    logger.debug(f"{path},{filepath.split(os.path.sep)[-1]}")
    if not filepath:
        raise HTTPException(status_code=499, detail=f"Shawl: No file found for build type amd64.exe")
    return FileResponse(path,filename=filename_wo_version)

@app.get('/tools/header_test')
async def header_test(remote_user: list = Header(...)):
     return {"User-Agent": remote_user}
@app.get('/tools/update_redis')
async def update_redis(remote_user: str = Header(...)):
    def generate_file_hash(file_path, hash_algorithm='sha256'):
        hash_func = hashlib.new(hash_algorithm)
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    if not remote_user=="tools":
        raise HTTPException(status_code=403, detail=f"{remote_user} not allowed to use ../tools/..")
    file_versions = []  # reset on initial
    special_versions = []  # reset on initial
    ignore_files_start="nosync_"

    for root, _, files in os.walk(directory_to_watch):
        for filename in files:
            if filename.startswith(ignore_files_start):  # excludes files starting with nosync_
                continue  # Skip files starting with nosync_
            filepath = os.path.join(root, filename)
            if os.path.isfile(filepath):
                """extract keys by path"""
                path_list = filepath.split(os.sep)
                oprs = path_list[os_dir_depth]
                hostname = path_list[hostname_dir_depth]
                filename = path_list[-1]

                if default_dirnames and hostname in default_dirnames:
                    # Spezialfall für Standarddateien
                    subfolder = path_list[folder_dir_depth] if len(path_list) > folder_dir_depth else "config"
                    if subfolder not in ["files", "scripts", "config"]:
                        subfolder = "config"
                    dir_entry = next((item for item in special_versions if item.get("special_dir") == hostname and item.get("os") == oprs), None)
                    if not dir_entry:
                        dir_entry = {
                            "special_dir": hostname,
                            "os": oprs,
                            "files": {},
                            "scripts": {},
                            "config": {}
                        }
                        special_versions.append(dir_entry)
                    dir_entry[subfolder][filename] = generate_file_hash(filepath)
                    continue
                elif std_dirnames and hostname in std_dirnames:
                    # Spezialfall für std-Dateien
                    subfolder = path_list[folder_dir_depth] if len(path_list) > folder_dir_depth else "scripts"
                    if subfolder not in ["files", "scripts", "config"]:
                        subfolder = "scripts"
                    dir_entry = next((item for item in special_versions if item.get("special_dir") == hostname and item.get("os") == oprs), None)
                    if not dir_entry:
                        dir_entry = {
                            "special_dir": hostname,
                            "os": oprs,
                            "files": {},
                            "scripts": {},
                            "config": {}
                        }
                        special_versions.append(dir_entry)
                    dir_entry[subfolder][filename] = generate_file_hash(filepath)
                    continue
                else:
                    # Normalfall
                    # Extrahiere zusätzliche Unterordner
                    folder = path_list[folder_dir_depth]

                    # Überprüfe, ob der extrahierte Ordner tatsächlich ein Verzeichnis ist
                    folder_path = ""
                    for idx, dir in enumerate(path_list):
                        if idx >= folder_dir_depth:
                            break
                        if idx == 0:
                            folder_path += f"{dir}"
                        else:
                            folder_path += f"/{dir}"
                    folder_path += f"/{folder}"

                    if not os.path.isdir(folder_path):  # Check if dir is correctly formed if not warn and continue
                        print(f"Folderpath not correct: {folder_path}, please check")
                        continue

                    # Suche nach bestehendem Hosteintrag
                    host_entry = next((item for item in file_versions if item.get("hostname") == hostname and item.get("os") == oprs), None)
                    if not host_entry:
                        host_entry = {
                            "hostname": hostname,
                            "os": oprs,
                            "dirs": {}
                        }
                        file_versions.append(host_entry)
                    if folder not in host_entry["dirs"]:
                        host_entry["dirs"][folder] = {}

                    host_entry["dirs"][folder][filename] = generate_file_hash(filepath)

    # Speichern der neuen Versionen in Redis
    redis_client.set('file_versions', json.dumps(file_versions))
    redis_client.set('special_versions', json.dumps(special_versions))

    logger.debug(f"{40*'#'} file versions DEBUG PRINT {40*'#'}")
    versioncount=0
    for my_dict in file_versions:
        versioncount+=1
        logger.debug(my_dict)
    specialversioncount=0
    for my_dict in special_versions:
        specialversioncount+=1
        logger.debug(my_dict)
    logger.info(f"Updated Redis with file_count: {versioncount} and specialfile_count: {specialversioncount}")
    return{
        "hostdir_count":versioncount,
        "special_dir_count":specialversioncount,
    }

if __name__ == '__main__':
    ##this is not executed if started with gunicorn, like its done via Docker :)

    import uvicorn

    def handle_exit(sig, frame):
        logger.info(f"Received exit signal {sig}...")
        # Gracefully shutdown the server
        uvicorn.Server.should_exit = True

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    uvicorn.run(app, host='0.0.0.0', port=8000,)
