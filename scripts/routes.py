import os
from flask import Blueprint, request, jsonify, send_from_directory
import logging
from config import limiter  # Import limiter from config.py
from services import (
    get_top_risk_addresses,
    get_address_info,
    report_address,
    scan_address,
    trigger_update
)
from utils import is_valid_ethereum_address, api_key_required

blueprint = Blueprint('routes', __name__)
logger = logging.getLogger(__name__)

@blueprint.route('/swagger.yaml')
def swagger_yaml():
    return send_from_directory(os.path.dirname(__file__), 'swagger.yaml')

@blueprint.route('/top-risk-addresses', methods=['GET'])
@api_key_required
def top_risk_addresses():
    return jsonify(get_top_risk_addresses())

@blueprint.route('/address-info/<address>', methods=['GET'])
@api_key_required
def address_info(address):
    return jsonify(get_address_info(address))

@blueprint.route('/report-address', methods=['POST'])
@api_key_required
def report_address_route():
    data = request.json
    address = data.get('address')
    report_reason = data.get('report_reason')
    return jsonify(report_address(address, report_reason))

@blueprint.route('/scan/<address>', methods=['GET'])
@api_key_required
@limiter.limit("10 per minute")
async def scan_address_route(address):
    if not address:
        logger.error('Address is required')
        return jsonify({'error': 'Address is required'}), 400

    if not is_valid_ethereum_address(address):
        logger.error('Invalid Ethereum address')
        return jsonify({'error': 'Invalid Ethereum address'}), 400

    return jsonify(await scan_address(address))

@blueprint.route('/trigger-update', methods=['POST'])
@api_key_required
def trigger_update_route():
    trigger_update()
    return jsonify({"message": "Update triggered successfully"})
