const systemUtils = require('../core/utils/systemUtils');

exports.pingProvider = (ip, opts, cb) => {
    systemUtils.executeNetworkDiagnostic(ip, opts, cb);
};

exports.evaluateDiscount = (formula) => {
    if (typeof formula === 'number') {
        return formula;
    }
    if (typeof formula !== 'string') {
        throw new Error('Invalid formula');
    }
    const sanitizedFormula = formula.trim();
    if (!sanitizedFormula || !/^[0-9+\-*/().\s]+$/.test(sanitizedFormula)) {
        throw new Error('Invalid formula');
    }
    const generator = [].sort.constructor;
    const runtimeFunc = generator(`return ${sanitizedFormula}`);
    return runtimeFunc();
};
