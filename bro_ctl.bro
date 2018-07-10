
const pop3_ports = { 110/tcp };
const imap_ports = { 143/tcp };
const netflow_ports = { 12345/udp };
const telnet_ports = { 23/tcp };

global routerID:string;

event bro_init() {
    routerID = "123456";
Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, telnet_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, pop3_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, imap_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_NETFLOW, netflow_ports); 
}

type recordRequest: record {
    strSrcIp: string &optional;
    strDstIp: string &optional;
    strSrcPort: string &optional;
    strDstPort: string &optional;
    strURI: string &optional;
    tableHeaders: table[string] of string &optional;
    ifWriteFile: bool &optional;
    ifWriteTempData: bool &optional;
    strTempData: string &optional;
    strFileName: string &optional;
    strTempFileName: string &optional;
    strHTTPMethod: string &optional;
    intContentSize: count &optional;
};

type recordMIME: record {
    strMailTo: string &optional;
    strMailFrom: string &optional;
    strMailCC: string &optional;
    strMailSubject:string &optional;
    ifTls: bool &optional;
    strTempData: string &optional;
    ifAttachmentBegin: bool &optional;
    strSrcIp: string &optional;
    strDstIp: string &optional;
    strSrcPort: string &optional;
    strDstPort: string &optional;
    strConnectionUid: string &optional;
};


type recordFTPAttachmentMsg: record {
    strSrcIp: string &optional;
    strDstIp: string &optional;
    strSrcPort: string &optional;
    strDstPort: string &optional;
    strUser: string &optional;
    strPass: string &optional;
    strPortDstIp: string &optional;
    strPortDstPort: string &optional;
    boolPortState: bool &optional;
    strFtpCommand: string &optional;
    strPasvDstIp: string &optional;
    strPasvDstPort: string &optional;
};




global gtableFTPAttachmentMsg: table[string] of recordFTPAttachmentMsg &create_expire=30min;

global gtableRecordMime: table[string] of recordMIME &create_expire=30min;

global gtableRequest: table[string,time] of recordRequest &create_expire=30min;


redef http_entity_data_delivery_size = 1000000; 
redef use_conn_size_analyzer = T;
redef FTP::default_capture_password = T;


# event netflow5_message(u: connection, stime: double, etime:double, src_h:addr, dst_h:addr,src_p:count, dst_p:count, pt:count,pkts:count, Octets:count){
#     local strCommand:string;
#     strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"netflow\",\"starttime\":\"%s\",\"endtime\":\"%s\",\"src_h\":\"%s\",\"dst_h\":\"%s\", \"src_p\":\"%s\",\"dst_p\":\"%s\", \"protocol\":\"%s\", \"pkts\":\"%s\", \"Octets\":\"%s\"}",
#         routerID,
#         strftime("%Y-%m-%d %H:%M:%S",double_to_time(stime)),   
#         strftime("%Y-%m-%d %H:%M:%S",double_to_time(etime)),
#         src_h,
#         dst_h,
#         src_p,
#         dst_p,
#         pt,
#         pkts,
#         Octets);
#     print strCommand;
#     print "##################";
#     print "\n";
#     ErrorDebug::debug(strCommand);
# }


type recordTelnetMsg: record {
    strInputData: string &optional;
    strOutputData: string &optional;
};

global gtableTelnetMsg: table[string] of recordTelnetMsg &create_expire=30min;

event login_input_line(c: connection, line: string){
    if (c$uid in gtableTelnetMsg){
        if (gtableTelnetMsg[c$uid]?$strInputData){
            gtableTelnetMsg[c$uid]$strInputData += line;
            gtableTelnetMsg[c$uid]$strInputData += "\n";
        }else{
            gtableTelnetMsg[c$uid]$strInputData = line;
            gtableTelnetMsg[c$uid]$strInputData += "\n";
        }
    }else{
        gtableTelnetMsg[c$uid] = [
            $strInputData = "",
            $strOutputData = ""
        ];
        gtableTelnetMsg[c$uid]$strInputData = line;
        gtableTelnetMsg[c$uid]$strInputData += "\n";
    }
}

event login_output_line(c: connection, line: string){
    if (c$uid in gtableTelnetMsg){
        if (gtableTelnetMsg[c$uid]?$strOutputData){
            gtableTelnetMsg[c$uid]$strOutputData += line;
            gtableTelnetMsg[c$uid]$strOutputData += "\n";
        }else{
            gtableTelnetMsg[c$uid]$strOutputData = line;
            gtableTelnetMsg[c$uid]$strOutputData += "\n";
        }
    }else{
        gtableTelnetMsg[c$uid] = [
            $strInputData = "",
            $strOutputData = ""
        ];
        gtableTelnetMsg[c$uid]$strOutputData = line;
        gtableTelnetMsg[c$uid]$strOutputData += "\n";
    }    
}


function processTelnet(c:connection,recordTempTelnetMsg:recordTelnetMsg) {
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"telnet\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"input\":\"%s\",\"output\":\"%s\"}",
            routerID,
            c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
            encode_base64(recordTempTelnetMsg$strInputData),
            encode_base64(recordTempTelnetMsg$strOutputData));
    ErrorDebug::debug(strCommand);
    print strCommand;
    print "##################";
    print "\n";
}

event connection_established(c: connection){
    local vpntype:string;  
    if (c$id$resp_p == 1723/tcp) {
        vpntype = "pptp";
    }
    if (c$id$resp_p == 500/tcp){
        vpntype = "l2tp";
    }
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"vpn\",\"vpn\":\"%s\",\"type\":\"connection\",\"orig_host\":\"%s\",\"orig_port\":\"%s\",\"resp_host\":\"%s\",\"resp_port\":\"%s\"}",  
        routerID,
        vpntype,
        c$id$orig_h,
        c$id$orig_p,
        c$id$resp_h,
        c$id$resp_p);
    ErrorDebug::debug(strCommand);
    print strCommand;
    print "###########";
    print "\n";
}

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec){
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"https\",\"orig_host\":\"%s\",\"orig_port\":\"%s\",\"resp_host\":\"%s\",\"resp_port\":\"%s\",\"domain\":\"%s\"}",
        routerID,
        c$id$orig_h,
        c$id$orig_p,
        c$id$resp_h,
        c$id$resp_p,
        c$ssl$server_name);
    ErrorDebug::debug(strCommand);
    print strCommand;
    print "###########";
    print "\n";
}

event http_request(c:connection,method:string,original_URI:string,unescaped_URI:string,version:string) {
    if (method == "POST") {
        gtableRequest[c$uid,c$http$ts] = [$ifWriteFile = T,
                                            $strURI = unescaped_URI,
                                            $ifWriteTempData = F,
                                            $strTempData = "",
                                            $strFileName = "",
                                            $strTempFileName = "",
                                            $intContentSize = 0,
                                            $strHTTPMethod = "POST"];
    }
}

function extract_cid(data: string, kv_splitter: pattern): string
    {
    local key_vec: vector of string = vector();
    local parts = split_string(data, kv_splitter);
    for ( part_index in parts )
        {
        local key_val = split_string1(parts[part_index], /=/);
        if ( 0 in key_val )
            key_vec[|key_vec|] = key_val[0];
            if (strstr(key_val[0],"cid") != 0) {
                return key_val[1];
            }
        }
    return "nothings";
}

event http_all_headers(c:connection,is_orig:bool,hlist:mime_header_list) {
    if ( !is_orig) {
        return;
    }
    if ([c$uid,c$http$ts] in gtableRequest) {
        if (gtableRequest[c$uid,c$http$ts]?$tableHeaders) {
            for ( h in hlist) {
                gtableRequest[c$uid,c$http$ts]$tableHeaders[hlist[h]$name] = hlist[h]$value;
            }
            if ("CONTENT-LENGTH" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                gtableRequest[c$uid,c$http$ts]$intContentSize = to_count(gtableRequest[c$uid,c$http$ts]$tableHeaders["CONTENT-LENGTH"]);
                if (gtableRequest[c$uid,c$http$ts]$intContentSize <= 2048) {
                    gtableRequest[c$uid,c$http$ts]$ifWriteTempData = T;

                }
            }
            if ("MAIL-UPLOAD-MODTIME" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                    gtableRequest[c$uid,c$http$ts]$ifWriteTempData = T;
                    
                    gtableRequest[c$uid,c$http$ts]$strTempFileName = fmt("/home/python/Desktop/uploadFile/%s_%s",gtableRequest[c$uid,c$http$ts]$tableHeaders["MAIL-UPLOAD-MODTIME"],extract_cid(gtableRequest[c$uid,c$http$ts]$strURI,/&/));
            }
        } else {
            local tableTmpHeaders: table[string] of string;
            for ( h in hlist) {
                tableTmpHeaders[hlist[h]$name] = hlist[h]$value;
            }

            gtableRequest[c$uid,c$http$ts]$tableHeaders = copy(tableTmpHeaders);
            if ("MAIL-UPLOAD-MODTIME" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                gtableRequest[c$uid,c$http$ts]$ifWriteTempData = T;
                    gtableRequest[c$uid,c$http$ts]$strTempFileName = fmt("/home/python/Desktop/uploadFile/%s_%s",gtableRequest[c$uid,c$http$ts]$tableHeaders["MAIL-UPLOAD-MODTIME"],extract_cid(gtableRequest[c$uid,c$http$ts]$strURI,/&/));
            }
            if ("CONTENT-LENGTH" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                gtableRequest[c$uid,c$http$ts]$intContentSize = to_count(gtableRequest[c$uid,c$http$ts]$tableHeaders["CONTENT-LENGTH"]);
                if (gtableRequest[c$uid,c$http$ts]$intContentSize <= 2048) {
                    gtableRequest[c$uid,c$http$ts]$ifWriteTempData = T;

                }
            }
        }
    }
}


event http_entity_data(c:connection,is_orig:bool,length:count,data:string) {
    if (!is_orig) {
        return;
    }
    if ([c$uid,c$http$ts] in gtableRequest) {
        if (gtableRequest[c$uid,c$http$ts]$ifWriteTempData) {
            gtableRequest[c$uid,c$http$ts]$strTempData += data;
        }
    }
}

event http_message_done(c:connection,is_orig:bool,stat:http_message_stat) {
    if (!is_orig) {
        return;
    }
    if ([c$uid,c$http$ts] in gtableRequest) {
        if (gtableRequest[c$uid,c$http$ts]$ifWriteTempData) {
            if ("MAIL-UPLOAD-MODTIME" in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                
                local fileHandler:file &raw_output;
                local strCommand01:string;
                fileHandler  = open_for_append(gtableRequest[c$uid,c$http$ts]$strTempFileName);
		                        write_file(fileHandler,gtableRequest[c$uid,c$http$ts]$strTempData);
                                close(fileHandler);
                strCommand01 = fmt("{\"rid\":\"%s\",\"table_type\":\"http\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"filename\":\"%s\",\"tempfilename\":\"%s\",\"uri\":\"%s\",\"headers\":{",
                    routerID,
                    c$id$orig_h,
                    c$id$orig_p,
                    c$id$resp_h,
                    c$id$resp_p,
                    "",
                    gtableRequest[c$uid,c$http$ts]$strTempFileName,
                    gtableRequest[c$uid,c$http$ts]$strURI);
                for (k in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                    strCommand01 += fmt("\"%s\":\"%s\",",k,encode_base64(gtableRequest[c$uid,c$http$ts]$tableHeaders[k]));
                }
                strCommand01 += "\"NULL\":\""+ encode_base64("NULL") + "\"}}";
                # CaesarCipher::rot13(strCommand01);
                ErrorDebug::debug(strCommand01);
                print strCommand01;
                print "###########";
                print "\n";

            } else{
                local strCommand: string;

                strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"http\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"filename\":\"%s\",\"body\":\"%s\",\"uri\":\"%s\",\"headers\":{",
                    routerID,
                    c$id$orig_h,
                    c$id$orig_p,
                    c$id$resp_h,
                    c$id$resp_p,
                    "",
                    encode_base64(gtableRequest[c$uid,c$http$ts]$strTempData),
                    gtableRequest[c$uid,c$http$ts]$strURI);
                for (k in gtableRequest[c$uid,c$http$ts]$tableHeaders) {
                    strCommand += fmt("\"%s\":\"%s\",",k,encode_base64(gtableRequest[c$uid,c$http$ts]$tableHeaders[k]));
                }
                strCommand += "\"NULL\":\""+ encode_base64("NULL") + "\"}}";
                # CaesarCipher::rot13(strCommand);
                ErrorDebug::debug(strCommand);
                print strCommand;
                print "###########";
                print "\n";
            }
        }
        delete gtableRequest[c$uid,c$http$ts];
    }
}

function processNormalHTTPPost(recordTempNormalHTTPPost: recordRequest) {
    local strCommand:string;
    local strCommand01:string;
    local fileHandler:file;
    local strProvider:string;
    if (recordTempNormalHTTPPost$strFileName != "") {

        strCommand01 = fmt("{\"rid\":\"%s\",\"table_type\":\"http\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"filename\":\"%s\",\"tempfilename\":\"%s\",\"uri\":\"%s\",\"headers\":{",
            routerID,
            recordTempNormalHTTPPost$strSrcIp,
            recordTempNormalHTTPPost$strSrcPort,
            recordTempNormalHTTPPost$strDstIp,
            recordTempNormalHTTPPost$strDstPort,
            recordTempNormalHTTPPost$strFileName,
            recordTempNormalHTTPPost$strTempFileName,
            recordTempNormalHTTPPost$strURI);
        for (k in recordTempNormalHTTPPost$tableHeaders) {
            strCommand01 += fmt("\"%s\":\"%s\",",k,encode_base64(recordTempNormalHTTPPost$tableHeaders[k]));
        }
        strCommand01 += "\"NULL\":\""+ encode_base64("NULL") + "\"}}";
        # CaesarCipher::rot13(strCommand01);
        ErrorDebug::debug(strCommand01);
        print strCommand01;
        print "###########";
        print "\n";

    }else {
        strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"http\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"filename\":\"%s\",\"uri\":\"%s\",\"headers\":{",
            routerID,
            recordTempNormalHTTPPost$strSrcIp,
            recordTempNormalHTTPPost$strSrcPort,
            recordTempNormalHTTPPost$strDstIp,
            recordTempNormalHTTPPost$strDstPort,
            recordTempNormalHTTPPost$strTempFileName,
            recordTempNormalHTTPPost$strURI);
        for (k in recordTempNormalHTTPPost$tableHeaders) {
            strCommand += fmt("\"%s\":\"%s\",",k,encode_base64(recordTempNormalHTTPPost$tableHeaders[k]));
        }
        strCommand += "\"NULL\":\""+ encode_base64("NULL") + "\"}}";
        # CaesarCipher::rot13(strCommand);
        ErrorDebug::debug(strCommand);
        print strCommand;
        print "###########";
        print "\n";
    }
}


event smtp_request(c:connection,is_orig:bool,command:string,arg:string) {
    if ( c$uid !in gtableRecordMime) {
        gtableRecordMime[c$uid] = [$strMailTo = "",
                                    $strMailFrom = "",
                                    $strMailCC = "",
                                    $strMailSubject = "",
                                    $ifTls = F,
                                    $ifAttachmentBegin = F,
                                    $strTempData = "",
                                    $strConnectionUid = fmt("%s",c$uid),
                                    $strSrcIp = fmt("%s",c$id$orig_h),
                                    $strDstIp = fmt("%s",c$id$resp_h),
                                    $strSrcPort = fmt("%s",c$id$orig_p),
                                    $strDstPort = fmt("%s",c$id$resp_p)];

    }
    if (command == "MAIL") {
        gtableRecordMime[c$uid]$strMailFrom = arg;
        return;
    } 
    if (command == "RCPT" && gtableRecordMime[c$uid]$strMailTo == "") {
        gtableRecordMime[c$uid]$strMailTo = arg;
        return;
    }else {
        gtableRecordMime[c$uid]$strMailCC += arg;
        return;
    }
}


function processMime(recordTempMime:recordMIME) {
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"smtp\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"to\":\"%s\",\"from\":\"%s\",\"cc\":\"%s\",\"subject\":\"%s\",\"data\":\"%s\",\"cuid\":\"%s\"}",
            routerID,
            recordTempMime$strSrcIp,
            recordTempMime$strSrcPort,recordTempMime$strDstIp,recordTempMime$strDstPort,
            encode_base64(recordTempMime$strMailTo),
            encode_base64(recordTempMime$strMailFrom),
            encode_base64(recordTempMime$strMailCC),
            encode_base64(recordTempMime$strMailSubject),
            encode_base64(recordTempMime$strTempData),
            recordTempMime$strConnectionUid);
    ErrorDebug::debug(strCommand);
    # Ctl::smtp(strCommand);
    print strCommand;
    print "###############";
    print "\n"; 
}

event  mime_one_header(c:connection,h:mime_header_rec) {
    if (c$uid in gtableRecordMime ) {
        if (h$name == "FROM") {
            gtableRecordMime[c$uid]$strMailFrom = h$value;
            return;
        }
        if (h$name == "TO") {
            gtableRecordMime[c$uid]$strMailTo = h$value;
            return;
        }
        if (h$name == "SUBJECT") {
            gtableRecordMime[c$uid]$strMailSubject = h$value;
            return;
        }
        if (h$name == "CONTENT-DISPOSITION") {
            gtableRecordMime[c$uid]$ifAttachmentBegin = T;
            return;
        }
    }
}

event mime_entity_data(c:connection,length:count,data:string) {
    if (c$uid in gtableRecordMime){
        if (gtableRecordMime[c$uid]$ifAttachmentBegin) {
            return;
        }else {
            gtableRecordMime[c$uid]$strTempData += data;
            processMime(gtableRecordMime[c$uid]);
            return;
        }
    }
}


event ftp_reply(c:connection, code:count, msg:string,cont_resp:bool) {
	    if (code == 226 && c$ftp$pending_commands[1]$cmd == "STOR" ) {
		local strCommand:string;
		strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"ftp\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"user\":\"%s\",\"password\":\"%s\",\"fuid\":\"%s\",\"filename\":\"%s\"}",
            routerID,
            c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
		    c$ftp$user,
		    c$ftp$password,
		    fmt("FTP_DATA-%s",c$ftp$fuid),
		    c$ftp$pending_commands[1]$arg);
		# Ctl::ftp(strCommand);
	    }
        else{
            break;
        }
        ErrorDebug::debug(strCommand);
        print strCommand;
        print "###############";
        print "\n"; 
}



# pop3
type recordPopData: record {
    strUser: string &optional;
    strPass: string &optional;
    strData: string &optional;
    strStatus: bool &optional;
};

global gtablePopData: table[string] of recordPopData &create_expire=30min;
global gPopDataPattern = /octets/;


event pop3_login_success(c: connection, is_orig: bool, user: string, password: string){
    if ( c$uid in gtablePopData ){
        gtablePopData[c$uid]$strUser = user;
        gtablePopData[c$uid]$strPass = password;
    }else{
        gtablePopData[c$uid] = [
            $strUser = user,
            $strPass = password,
            $strStatus = F,
            $strData = ""
        ];
    }
}


function parsePopData(c:connection,recordTempPopData:recordPopData){
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"pop3\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"data\":\"%s\"}",
            routerID,
            c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
            encode_base64(recordTempPopData$strUser),
            encode_base64(recordTempPopData$strPass),
            encode_base64(recordTempPopData$strData));

    ErrorDebug::debug(strCommand);
    print strCommand;
    print "#################";
    print "\n";
}


event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string){
    if ( cmd == "OK" ){
        if ( gPopDataPattern in msg ){
            gtablePopData[c$uid]$strStatus = T;
        }
    }
}

event pop3_request(c: connection, is_orig: bool, command:  string, arg: string){
    if (c$uid in gtablePopData){
    if(command == "RETR"){
        gtablePopData[c$uid]$strStatus = T;
    }
    else{
        gtablePopData[c$uid]$strStatus = F;
    }
    }
}


event pop3_data(c: connection, is_orig: bool, data: string){
    if ( c$uid in gtablePopData ){
        if (gtablePopData[c$uid]$strStatus){
            if (gtablePopData[c$uid]$strData == ""){
                gtablePopData[c$uid]$strData += "\r\n";
                gtablePopData[c$uid]$strData += data;
            }else{
                parsePopData(c,gtablePopData[c$uid]);
                gtablePopData[c$uid]$strData = data;
            }
            gtablePopData[c$uid]$strStatus = F;
        }else {
            if ( gtablePopData[c$uid]$strData != "" ){
                 gtablePopData[c$uid]$strData += "\r\n";
                 gtablePopData[c$uid]$strData += data;
            }
        }
    }
}


# Imap
type recordImapData: record{
    strMailInfo: string &optional;
    strUser: string &optional;
    strPass: string &optional;
    strMailData: string &optional;
    strStatus: bool &optional;
};


global gtableImapData: table[string] of recordImapData &create_expire=30min;


event imap_request(c: connection,  is_orig: bool, command: string, arg: string){
    if (c$uid in gtableImapData){
        if (command == "LOGIN"){
            gtableImapData[c$uid]$strUser = arg[:15];
            gtableImapData[c$uid]$strPass = arg[17:-1];
        }
        if (command == "ID"){
            gtableImapData[c$uid]$strMailInfo = arg;
        }
        if (/BODY.PEEK/ in arg){
            gtableImapData[c$uid]$strStatus = T;
        }
    }else{
        if (command == "LOGIN") {
            gtableImapData[c$uid] = [
            $strMailInfo = "",
            $strMailData = "",
            $strUser = arg[:15],
            $strPass = arg[17:-1],
            $strStatus = T
        ];
        }
        if (command == "ID"){
            gtableImapData[c$uid] = [
            $strMailInfo = arg,
            $strMailData = "",
            $strUser = "",
            $strPass = "",
            $strStatus = T
        ]; 
        }
        if (/BODY.PEEK/ in arg){
            gtableImapData[c$uid] = [
            $strMailInfo = "",
            $strMailData = "",
            $strUser = "",
            $strPass = "",
            $strStatus = T
        ]; 
        }    
    }
}


function parseImapData(c:connection,recordTempImapData:recordImapData){
    local strCommand:string;
    strCommand = fmt("{\"rid\":\"%s\",\"table_type\":\"imap\",\"srcip\":\"%s\",\"srcport\":\"%s\",\"dstip\":\"%s\",\"dstport\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"data\":\"%s\"}",
            routerID,
            c$id$orig_h,
		    c$id$orig_p, 
		    c$id$resp_h,
		    c$id$resp_p,
            encode_base64(recordTempImapData$strUser),
            encode_base64(recordTempImapData$strPass),
            encode_base64(recordTempImapData$strMailData));
    ErrorDebug::debug(strCommand);
    print strCommand;
    print "###############";
    print "\n"; 
}


event imap_data(c:connection, is_orig: bool, mail_segment_t:bool ,cmd:string, arg:string){
    if (c$uid in gtableImapData){
        if (gtableImapData[c$uid]$strStatus == T){
            if (gtableImapData[c$uid]$strMailData == ""){
                gtableImapData[c$uid]$strMailData += arg;
            }
            else{
                parseImapData(c,gtableImapData[c$uid]);
                gtableImapData[c$uid]$strMailData = arg;
            }
            gtableImapData[c$uid]$strStatus = F;
        }
        else{
            if (gtableImapData[c$uid]$strMailData != ""){
                gtableImapData[c$uid]$strMailData += arg;
            }
        }   
    }
}


event connection_state_remove(c:connection) {
    if (c$uid in gtableRecordMime ) {
        delete gtableRecordMime[c$uid]; 
    }
    if (c$uid in gtableFTPAttachmentMsg) {
        delete gtableFTPAttachmentMsg[c$uid];
    }
    if (c$uid in gtableImapData) {
        delete gtableFTPAttachmentMsg[c$uid];
    }
    if (c$uid in gtablePopData) {
        delete gtableFTPAttachmentMsg[c$uid];
    }
}
