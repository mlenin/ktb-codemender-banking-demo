const systemUtils = require('../core/utils/systemUtils');

exports.pingProvider = (ip, opts, cb) => {
    systemUtils.executeNetworkDiagnostic(ip, opts, cb);
};

exports.evaluateDiscount = (formula) => {
    if (typeof formula !== 'string' || !/^[0-9+\-*/().\s]+$/.test(formula)) {
        throw new Error('Security policy violation: non-arithmetic expression blocked');
    }
    const sanitized = formula.replace(/[^0-9+\-*/().]/g, '');
    return Number(Function('"use strict"; return (' + sanitized + ')')());
};
