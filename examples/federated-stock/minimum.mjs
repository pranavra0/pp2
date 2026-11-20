export default ({storage}, {sku}) => storage.get(`minimum/${sku}`);
