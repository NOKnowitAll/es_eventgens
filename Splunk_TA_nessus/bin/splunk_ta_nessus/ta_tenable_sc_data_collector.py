import time
import json
import httplib2

import splunktalib.common.util as util

import splunktaucclib.data_collection.ta_data_client as dc
import splunktaucclib.data_collection.ta_consts as c
import splunktaucclib.common.log as stulog

import ta_tenable_consts as consts
import ta_tenable_util
import security_center


@dc.client_adatper
def do_job_one_time(all_conf_contents, task_config, ckpt):
    return _do_job_one_time(all_conf_contents, task_config, ckpt)


def _do_job_one_time(all_conf_contents, task_config, ckpt):
    logger_prefix = _get_logger_prefix(task_config)
    stulog.logger.info("{} Enter _do_job_one_time().".format(logger_prefix))
    server_info = _get_server_info(all_conf_contents, task_config)
    url = server_info.get(consts.url)
    username = server_info.get(consts.username)
    password = server_info.get(consts.password)

    proxy_config = all_conf_contents[consts.global_settings][
        consts.nessus_proxy]
    enabled = util.is_true(proxy_config.get('proxy_enabled', ''))

    tenable_sc_settings = all_conf_contents[consts.global_settings][
        consts.tenable_sc_settings]
    disable_ssl_certificate_validation = util.is_true(tenable_sc_settings.get(
        'disable_ssl_certificate_validation'))
    stulog.logger.info(
        '{} The disable_ssl_certificate_validation is {}'.format(
            logger_prefix, disable_ssl_certificate_validation))
    try:
        if enabled:
            stulog.logger.info("{} Proxy is enabled.".format(logger_prefix))
            sc = security_center.get_security_center(
                url,
                disable_ssl_certificate_validation,
                username,
                password,
                proxy_config,
                logger_prefix=logger_prefix)
        else:
            stulog.logger.info("{} Proxy is disabled.".format(logger_prefix))
            sc = security_center.get_security_center(
                url,
                disable_ssl_certificate_validation,
                username,
                password,
                logger_prefix=logger_prefix)
    except httplib2.SSLHandshakeError:
        stulog.logger.warn(
            "{} [SSL: CERTIFICATE_VERIFY_FAILED] certificate verification failed. "
            "The certificate of the https server {} is not trusted, "
            "this add-on will proceed to connect with this certificate. "
            "You may need to check the certificate and "
            "refer to the documentation and add it to the trust list.".format(
                logger_prefix, url))
        if enabled:
            stulog.logger.info("{} Proxy is enabled.".format(logger_prefix))
            sc = security_center.get_security_center(
                url,
                True,
                username,
                password,
                proxy_config,
                logger_prefix=logger_prefix)
        else:
            stulog.logger.info("{} Proxy is disabled.".format(logger_prefix))
            sc = security_center.get_security_center(
                url,
                True,
                username,
                password,
                logger_prefix=logger_prefix)

    # According to the data value, invoke different method
    data = task_config.get(c.data)
    stulog.logger.info("{} The data field for tenable_sc_inputs is {}".format(
        logger_prefix, data))
    if data == consts.sc_vulnerability:
        return _process_sc_vulnerability(sc, task_config, ckpt, server_info,
                                         logger_prefix)
    else:
        raise Exception('Cannot process data={}'.format(data))
    stulog.logger.info("{} Exit _do_job_one_time().".format(logger_prefix))


def _get_server_info(global_config, task_config):
    server_name = task_config[consts.server]
    return global_config[consts.servers][server_name]


def cmp2(x, y):
    try:
        return cmp(int(x), int(y))
    except ValueError:
        return cmp(x, y)


def _process_sc_vulnerability(sc, task_config, ckpt, server_info,
                              logger_prefix):
    _pre_process_ckpt(sc, task_config, ckpt, logger_prefix)
    stop = yield None, ckpt
    stulog.logger.info("{} Finish process checkpoint.".format(logger_prefix))
    if stop:
        return
    server_url = server_info.get(consts.url)
    sub_ckpt = ckpt.get(server_url)
    scan_results = sub_ckpt.get('scan_results')
    host = ta_tenable_util.extract_host(server_url)
    index = task_config.get(c.index)
    batch_size = task_config.get(c.batch_size)
    if batch_size is None:
        step = 10000
    else:
        step = int(batch_size)
    stulog.logger.info("{} The batch_size is {}.".format(logger_prefix, step))

    for scan_id in sorted(scan_results.iterkeys(), cmp=cmp2):
        scan_info = scan_results[scan_id]
        status = scan_info.get('status')
        if status != 'Partial' and status != 'Completed':
            continue
        if scan_info.get('total_records') is None:
            continue
        start_offset = scan_info.get('received')
        end_offset = scan_info.get('received')
        sourcetype = 'tenable:sc:vuln'
        source = 'scan_result_id:{}'.format(scan_id)
        try:
            scan_result = sc.get_scan_result(scan_id)
            scan_result_info = {'id': scan_id,
                                'name': scan_result.get('name'),
                                'importStart': scan_result.get('importStart'),
                                'importFinish':
                                scan_result.get('importFinish'),
                                'createdTime': scan_result.get('createdTime'),
                                'startTime': scan_result.get('startTime'),
                                'finishTime': scan_result.get('finishTime')}

            if scan_info.get('total_records') == 0:
                raw_data = {'_scan_result_info': scan_result_info,
                            '_is_scan_result_empty': 1}
                event = dc.build_event(
                    host=host,
                    source=source,
                    sourcetype=sourcetype,
                    time=scan_result_info.get('importStart'),
                    index=index,
                    raw_data=json.dumps(raw_data))
                stop = yield event, ckpt

            while scan_info.get('received') < scan_info.get('total_records'):
                end_offset += step
                vuln_list = sc.get_vulns(scan_id, start_offset, end_offset)
                scan_info['received'] += len(vuln_list)
                events = []
                for vuln in vuln_list:
                    vuln['_scan_result_info'] = scan_result_info
                    vuln['_is_scan_result_empty'] = 0
                    events.append(dc.build_event(host=host,
                                                 source=source,
                                                 sourcetype=sourcetype,
                                                 time=vuln.get('lastSeen'),
                                                 index=index,
                                                 raw_data=json.dumps(vuln)))
                stop = yield events, ckpt
                if stop:
                    break
                start_offset = end_offset
        except security_center.APIError as e:
            if e.error_code == 147:
                stulog.logger.warn('{} error_msg={}'.format(logger_prefix,
                                                            e.error_msg))
                del sub_ckpt['scan_results'][scan_id]
            else:
                raise e

        if scan_info.get('received') >= scan_info.get('total_records'):
            del scan_results[scan_id]
            stop = yield None, ckpt
        if stop:
            return


def _pre_process_ckpt(sc, task_config, ckpt, logger_prefix):
    server_url = sc.get_server_url()
    start_time = task_config.get(consts.start_time)
    start_time = ta_tenable_util.iso8601_to_timestamp(start_time)
    end_time = time.time()
    if start_time > end_time:
        raise Exception(
            'The start_time must be less than or equal to end_time')
    stulog.logger.info(
        '{logger_prefix} Perform a request to {server_url}, '
        'the start time is {start_time}'.format(logger_prefix=logger_prefix,
                                                server_url=server_url,
                                                start_time=start_time))
    stulog.logger.info(
        '{logger_prefix} Perform a request to {server_url}, '
        'the end time is {end_time}'.format(logger_prefix=logger_prefix,
                                            server_url=server_url,
                                            end_time=end_time))
    sub_ckpt = ckpt.get(server_url)
    sub_ckpt = sub_ckpt if sub_ckpt else {}
    ckpt_start_time = sub_ckpt.get('start_time')
    ckpt_end_time = sub_ckpt.get('end_time')

    if start_time != ckpt_start_time:
        stulog.logger.info(
            '{} The start time in conf not equal to the start time in checkpoint, '
            'reinitialize checkpoint for {}'.format(logger_prefix, server_url))
        sub_ckpt = {}
        job_start_time = start_time
    else:
        job_start_time = ckpt_end_time + 1
    stulog.logger.info('{} The start time is {} and the end time is {}'.format(
        logger_prefix, job_start_time, end_time))
    usable_scan_result = sc.perform_request(
        'GET', 'scanResult?filter=usable&startTime={}&endTime={}'.format(
            job_start_time, end_time))

    sub_ckpt['start_time'] = start_time
    sub_ckpt['end_time'] = end_time
    if not sub_ckpt.get('scan_results'):
        sub_ckpt['scan_results'] = {}
    for scan_result in usable_scan_result.get('usable'):
        scan_id = scan_result.get('id')
        status = scan_result.get('status')
        if sub_ckpt['scan_results'].get(scan_id):
            sub_ckpt['scan_results'][scan_id].update({'status': status})
        else:
            sub_ckpt['scan_results'][scan_id] = {'status': status}

        if status != 'Partial' and status != 'Completed':
            continue

        if sub_ckpt['scan_results'][scan_id].get('total_records'):
            continue
        try:
            total_records = sc.get_total_records_for_vuln(scan_id)
            sub_ckpt['scan_results'][scan_id].update(
                {'total_records': total_records,
                 'received': 0})
        except security_center.APIError as e:
            if e.error_code == 143:
                stulog.logger.warn('{} error_msg={}'.format(logger_prefix,
                                                            e.error_msg))
                del sub_ckpt['scan_results'][scan_id]
            elif e.error_code == 147:
                stulog.logger.warn('{} error_msg={}'.format(logger_prefix,
                                                            e.error_msg))
                del sub_ckpt['scan_results'][scan_id]
            else:
                raise e

    scan_results = sub_ckpt.get('scan_results')
    for (scan_id, scan_info) in scan_results.items():
        status = scan_info.get('status')
        if status == 'Partial' or status == 'Completed':
            if scan_info.get('total_records') is not None:
                continue
        try:
            scan_result = sc.get_scan_result(scan_id)
            status = scan_result.get('status')
            if status != 'Partial' and status != 'Completed':
                continue

            total_records = sc.get_total_records_for_vuln(scan_id)
            scan_info.update({'status': status,
                              'total_records': total_records,
                              'received': 0})
        except security_center.APIError as e:
            if e.error_code == 143:
                stulog.logger.warn('{} error_msg={}'.format(logger_prefix,
                                                            e.error_msg))
                del sub_ckpt['scan_results'][scan_id]
            elif e.error_code == 147:
                stulog.logger.warn('{} error_msg={}'.format(logger_prefix,
                                                            e.error_msg))
                del sub_ckpt['scan_results'][scan_id]
            else:
                raise e

    ckpt[server_url] = sub_ckpt


def _get_logger_prefix(task_config):
    pairs = ['{}="{}"'.format(c.stanza_name, task_config[c.stanza_name])]
    for key in task_config[c.divide_key]:
        pairs.append('{}="{}"'.format(key, task_config[key]))
    return "[{}]".format(" ".join(pairs))
