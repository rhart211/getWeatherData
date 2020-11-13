import logging
import requests
import os.path
import configparser
from influxdb import InfluxDBClient
from datetime import datetime


def create_logger(LOG_FILE, DEFAULT_LOGGING='info'):
    """
    configure the client logging
    """
    FORMAT = ('%(asctime)-15s %(threadName)-15s %(levelname)-8s %(module)-15s:%(lineno)-8s %(message)s')
    logging.basicConfig(format=FORMAT)
    log = logging.getLogger()
    main_base = os.path.dirname(__file__)
    LOGFILE = os.path.join(main_base, LOG_FILE)
    file_hdlr = logging.FileHandler(LOGFILE)
    file_format = logging.Formatter(FORMAT)
    file_hdlr.setFormatter(file_format)
    log.addHandler(file_hdlr)
    numeric_level = getattr(logging, DEFAULT_LOGGING.upper())
    log.setLevel(numeric_level)
    return log

def read_config(CONFIG_FILE):
    """
    Load Credentials and Configuration from Config
    """
    main_base = os.path.dirname(__file__)
    DEFAULT_CONFIG = os.path.join(main_base, CONFIG_FILE)

    config = configparser.ConfigParser()
    config.read(DEFAULT_CONFIG)

    log_file = config['global']['logfile']

    try:
        netatmo_auth = (
            config["netatmo"]["client_id"],
            config["netatmo"]["client_secret"],
            config["netatmo"]["username"],
            config["netatmo"]["password"],
        )
        if config.has_option("netatmo", "default_device_id"):
            default_device_id = config["netatmo"]["default_device_id"]
    except:
        netatmo_auth(None, None, None, None)

    try:
        influx_auth = (
            config['influxdb']['host'],
            config['influxdb']['port'],
            config['influxdb']['user'],
            config['influxdb']['password'],
            config['influxdb']['dbname']
        )
    except:
        influx_auth(None, None, None, None, None)

    return log_file, netatmo_auth, influx_auth, default_device_id

def generate_access_token(log, auth):
    """
    generate netatmo access token
    """

    payload = {'grant_type': 'password',
               'username': auth[2],
               'password': auth[3],
               'client_id': auth[0],
               'client_secret': auth[1],
               'scope': 'read_station'}
    try:
        log.info("Request Netatmo Access token")
        response = requests.post("https://api.netatmo.com/oauth2/token", data=payload)
        response.raise_for_status()
        access_token = response.json()["access_token"]
        refresh_token = response.json()["refresh_token"]
        scope = response.json()["scope"]
        log.debug("Access token: {0}".format(access_token))
        log.debug("Refresh token: {0}".format(refresh_token))
        log.debug("Scopes: {0}".format(scope))
        log.debug("Expires in {0}".format(response.json()["expires_in"]))
        log.debug("Expire in {0}".format(response.json()["expire_in"]))

    except requests.exceptions.HTTPError as error:
        log.error("%d %s", error.response.status_code, error.response.text)

    return access_token


def request_station_data(log, access_token, default_device_id):
    """
    request netatmo data
    """
    params = {
        'device_id': default_device_id
    }

    headers = {"Authorization": "Bearer {0}".format(access_token)}

    log.info('Request Indoor Station Data')
    response = requests.post("https://api.netatmo.com/api/getstationsdata", params=params, headers=headers)
    response.raise_for_status()
    indoor_data = response.json()['body']['devices'][0]['dashboard_data']
    indoor_rem = ['min_temp', 'max_temp', 'date_max_temp', 'date_min_temp']
    [indoor_data.pop(key) for key in indoor_rem]
    indoor_data['wifi_status'] = response.json()['body']['devices'][0]['wifi_status']
    indoor_data['altitude'] = response.json()['body']['devices'][0]['place']['altitude']
    indoor_data['timezone'] = response.json()['body']['devices'][0]['place']['timezone']
    indoor_data['indoor_temp_trend'] = indoor_data.pop('temp_trend')
    indoor_data['indoor_pressure_trend'] = indoor_data.pop('pressure_trend')
    indoor_data['indoor_Temperature'] = indoor_data.pop('Temperature')
    indoor_data['indoor_Humidity'] = indoor_data.pop('Humidity')

    log.debug(indoor_data)

    outdoor_data = response.json()['body']['devices'][0]['modules'][0]['dashboard_data']
    outdoor_rem = ['min_temp', 'max_temp', 'date_max_temp', 'date_min_temp']
    [outdoor_data.pop(key) for key in outdoor_rem]
    outdoor_data['battery_percent'] = response.json()['body']['devices'][0]['modules'][0]['battery_percent']
    outdoor_data['battery_vp'] = response.json()['body']['devices'][0]['modules'][0]['battery_vp']
    outdoor_data['rf_status'] = response.json()['body']['devices'][0]['modules'][0]['rf_status']
    outdoor_data['outdoor_temp_trend'] = outdoor_data.pop('temp_trend')
    outdoor_data['outdoor_Temperature'] = outdoor_data.pop('Temperature')
    outdoor_data['outdoor_Humidity'] = outdoor_data.pop('Humidity')
    log.debug(outdoor_data)

    return indoor_data, outdoor_data

def toInfluxFormat(log, module_name, sensor_type, time_utc, measurement):

    if isinstance(measurement, str):
        json_body = [
            {
                "measurement": sensor_type,
                "tags": {
                    "sensor": module_name,
                },
                "time": datetime.fromtimestamp(time_utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "fields": {
                    "value": str(measurement)
                }
            }
        ]

    else:
        json_body = [
            {
                "measurement": sensor_type,
                "tags": {
                    "sensor_type": module_name,
                },
                "time": datetime.fromtimestamp(time_utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "fields": {
                    "value": float(measurement)
                }
            }
        ]

    log.debug(json_body)

    return json_body

def write_points(log, module_name, sensor_data, influx_client):
    time = sensor_data['time_utc']
    sensor_data.pop('time_utc')

    for k, v in sensor_data.items():
        json_body = toInfluxFormat(log, module_name, k, time, v)
        influx_client.write_points(json_body)


def main():
    requests.packages.urllib3.disable_warnings()
    log_file, netatmo_auth, influx_auth, default_device_id = read_config('config')
    log = create_logger(log_file, 'debug')
    access_token = generate_access_token(log, netatmo_auth)
    indoor_data, outdoor_data = request_station_data(log, access_token, default_device_id)
    influx_client = InfluxDBClient(influx_auth[0], influx_auth[1], influx_auth[2], influx_auth[3], influx_auth[4], ssl=True)
    write_points(log, 'Indoor_Sensor', indoor_data, influx_client)
    write_points(log, 'Outdoor_Sensor', outdoor_data, influx_client)
    influx_client.close()

if __name__ == '__main__':
    main()
