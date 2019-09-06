# coding:utf8
import os
import logging

from flask import Flask, request, abort
from wechatpy import parse_message, create_reply
from wechatpy.utils import check_signature
from wechatpy.exceptions import (
    InvalidSignatureException,
    InvalidAppIdException,
)

from db import fetchone_by_name

# set token or get from environments
TOKEN = os.getenv('WECHAT_TOKEN', '123456')
# AES_KEY = os.getenv('WECHAT_AES_KEY', '')
APPID = os.getenv('WECHAT_APPID', '')
ENCODING_AES_KEY = os.getenv('WECHAT_EAESKEY', '')

app = Flask(__name__)
gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers

category = {
    1: "可回收垃圾",
    2: "有害垃圾",
    4: "湿垃圾",
    8: "干垃圾",
    16: "大件垃圾"
}


@app.after_request
def after_request(response):
    resp = response.data.decode('utf-8')
    app.logger.info(resp)
    return response


@app.route("/")
def index():
    return "hello, world"


@app.route('/wechat', methods=['GET', 'POST'])
def wechat():
    signature = request.args.get('signature', '')
    timestamp = request.args.get('timestamp', '')
    nonce = request.args.get('nonce', '')
    encrypt_type = request.args.get('encrypt_type', 'raw')
    msg_signature = request.args.get('msg_signature', '')
    try:
        check_signature(TOKEN, signature, timestamp, nonce)
    except InvalidSignatureException:
        abort(403)
    if request.method == 'GET':
        echo_str = request.args.get('echostr', '')
        return echo_str

    # POST request
    if encrypt_type == 'raw':
        # plaintext mode
        msg = parse_message(request.data)
        if msg.type == 'text':
            reply = create_reply(msg.content, msg)
        else:
            reply = create_reply('Sorry, can not handle this for now', msg)
        return reply.render()
    else:
        # encryption mode
        from wechatpy.crypto import WeChatCrypto

        crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, APPID)
        try:
            msg = crypto.decrypt_message(
                request.data,
                msg_signature,
                timestamp,
                nonce
            )
        except (InvalidSignatureException, InvalidAppIdException):
            abort(403)
        else:
            msg = parse_message(msg)
            app.logger.info(msg)
            if msg.type == 'text':
                result = fetchone_by_name(msg.content)
                if result:
                    reply_msg = category.get(result, "知不道")
                else:
                    reply_msg = "抱歉, Feed还小，不知道“{0}”是什么垃圾".format(msg.content)
                reply = create_reply(reply_msg, msg)
            else:
                reply = create_reply('Sorry, can not handle this for now', msg)
            app.logger.info("test")

            return crypto.encrypt_message("".join(reply.render().split()), nonce, timestamp)


@app.route("/test", methods=["POST"])
def test():
    params = request.get_json()
    msg = params["msg"]
    result = fetchone_by_name(msg)
    if result:
        reply_msg = category.get(result)
    else:
        reply_msg = "抱歉, Feed还小，不知道“{0}”是什么垃圾？".format(msg)
    return reply_msg


if __name__ == '__main__':
    app.run('127.0.0.1', 5001, debug=True)
