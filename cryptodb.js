'use strict';

function CryptoDB(cryptic, datastore, memstore, secretKey, passwordKey, recoverOnLoad=false, autosaveIndex=false) {

  let SECRET = null;
  let PASSWORD = null;
  let RECOVERY = null;
  let indexName = null;

  const files = datastore;
  const index = memstore;

  let loading = false;
  let loaded = false;
  let saving = false;
  let unsaved = false;

  const hashPath = async (path) => {
    let exists = await index.get(path);
    if (exists && exists.value) {
      return exists.value;
    }
    return await cryptic.hmacSign(SECRET, path);
  };

  const Load = async () => {
    if (loaded) {
      return true;
    }
    if (loading) {
      return resume();
    }
    loading = true;

    SECRET = cryptic.decode(await cryptic.kdf(cryptic.fromText(secretKey), cryptic.fromText(passwordKey), cryptic.fromText('SECRET'), 256));
    PASSWORD = cryptic.decode(await cryptic.kdf(cryptic.fromText(passwordKey), cryptic.fromText(secretKey), cryptic.fromText('PASSWORD'), 256));
    RECOVERY = cryptic.decode(await cryptic.kdf(PASSWORD, SECRET, cryptic.fromText('RECOVERY'), 256));
 
    indexName = await cryptic.kdf(SECRET, PASSWORD, cryptic.fromText('INDEX'), 256);
    let indexExists = (await files.get(indexName)).value;
    if (indexExists) {
      let decrypted = await Decrypt(indexName, indexExists);
      await index.importDB(decrypted);
    }

    if (recoverOnLoad) {
      await recoverIndex();
    }

    loaded = true;
    loading = false;
    return loaded;

  };

  const resume = () => {
    return new Promise((resolve,reject) => {
      setTimeout(()=>{
        resolve(Load());
      }, 100);
    });
  };

  const Encrypt = async (path, data) => {
    let random = cryptic.random(32);
    let salt = cryptic.combine(random, cryptic.fromText(path));
    let bits = await cryptic.kdf(cryptic.combine(PASSWORD), salt, cryptic.fromText('ENCRYPT'), 512);
    let key = await cryptic.decode(bits).slice(0, 32);
    let ad = await cryptic.decode(bits).slice(32, 64);
    let encrypted = await cryptic.encrypt(JSON.stringify(data), key, ad);
    let recover = await cryptic.kdf(RECOVERY, random, cryptic.fromText("RECOVER"), 256)
    let recovery = await cryptic.encrypt(path, cryptic.decode(recover));
    let payload = cryptic.encode(random) + '.' + encrypted + '.' + recovery;
    return payload;
  };

  const Decrypt = async (path, payload) => {
    let random = payload.split('.')[0];
    let encrypted = payload.split('.').slice(1).join('.');
    let salt = cryptic.combine(random, cryptic.fromText(path));
    let bits = await cryptic.kdf(cryptic.combine(PASSWORD), salt, cryptic.fromText('ENCRYPT'), 512);
    let key = await cryptic.decode(bits).slice(0, 32);
    let ad = await cryptic.decode(bits).slice(32, 64);
    let decrypted = await cryptic.decrypt(encrypted, key, ad);
    return JSON.parse(decrypted);
  };

  const Put = async (path, data) => {
    if (!loaded) {
      await Load();
    }
    let hash = await hashPath(path);
    let encrypted = await Encrypt(path, data);
    await files.put(hash, encrypted);
    await index.put(path, hash);
    await save();
    let e = {
      "event": "write",
      "timestamp": Date.now(),
      "key": path
    };
    return e;
  };

  const List = async (query={}) => {
    if (!loaded) {
      await Load();
    }
    let body = Object.assign({}, query);
    body.values = true;
    let list = await index.list(body);
    if (query.values) {
      let promises = [];
      for (let i = 0; i < list.length; i++) {
        promises.push(Get(list[i].key));
      }
      let results = await Promise.all(promises);
      return results;
    } else {
      return list.map(file => {
        return file.key;
      });
    }
  };

  const Get = async (path) => {
    if (!loaded) {
      await Load();
    }
    let hash = await hashPath(path);
    let encrypted = (await files.get(hash)).value;
    let decrypted = null;
    if (encrypted) {
      decrypted = await Decrypt(path, encrypted);
    }
    return {
      "key": path,
      "value": decrypted
    };
  };

  const Del = async (paths) => {
    if (!loaded) {
      await Load();
    }
    let keyPaths = paths;
    if (typeof paths === 'string') {
      keyPaths = [paths];
    }
    let promises = [];
    for (let i = 0; i < keyPaths.length; i++) {
      promises.push((async () => {
        let hash = await hashPath(keyPaths[i]);
        await files.del(hash);
        await index.del(keyPaths[i]);
      })());
    }
    await Promise.all(promises);
    await save();
    let e = {
      "event": "delete",
      "timestamp": Date.now(),
      "keys": keyPaths
    };
    return e;
  };

  const exportDB = async () => {
    if (!loaded) {
      await Load();
    }
    return List({"values":true});
  };

  const importDB = async (data) => {
    if (!loaded) {
      await Load();
    }
    let paths = [];
    for(let i = 0; i < data.length; i++) {
      paths.push(data[i].key);
      await Put(data[i].key, data[i].value);
    }
    await save();
    let e = {
      "event":"importDB",
      "timestamp":Date.now(),
      "keys":paths
    };
    return e;
  };

  const deleteDB = async () => {
    let deleted = await files.deleteDB();
    await index.deleteDB();
    loaded = false;
    let e = {
      "event": "deleteDB",
      "timestamp":Date.now()
    };
    return deleted;
  };

  const saveIndex = async (force=false) => {
    if (saving && !force) {
      unsaved = true;
      return true;
    }
    unsaved = false;
    saving = true;
    return Encrypt(indexName, await index.exportDB()).then(encryptedFS=>{
      return files.put(indexName, encryptedFS).then(async ok=>{
        saving = false;
        if (unsaved) {
          return save(true);
        }
        return true;
      });
    });
  };

  const save = async () => {
    if (autosaveIndex) {
      return saveIndex();
    } else {
      return true;
    }
  };

  const importIndex = async (indexData) => {
    let promises = [];
    for(let i = 0; i < indexData.length; i++) {
      promises.push(hashPath(indexData[i]).then(result=>{
        return {"key":indexData[i], "value":result};
      }));
    }
    let results = await Promise.all(promises);
    await index.importDB(results);
    await save();
    return true;
  };

  const exportIndex = async () => {
    if (!loaded) {
      await Load();
    }
    return index.list();
  };

  const deleteIndex = async () => {
    await files.del(indexName);
    await index.deleteDB();
    return true;    
  };

  const recoverIndex = async () => {
    let items = await datastore.list({"values":true});
    let recovered = [];
    for (let i = 0; i < items.length; i++) {
      if (items[i].value && typeof items[i].value === 'string' && items[i].value.split('.').length === 5) {
        let parts = items[i].value.split('.');
        let random = parts[0];
        let recover = await cryptic.kdf(RECOVERY, cryptic.decode(random), cryptic.fromText("RECOVER"), 256);
        let path = await cryptic.decrypt(parts[3] + '.' + parts[4], cryptic.decode(recover)).catch(err=>{return null;});
        if (path && items[i].key !== path) {
          recovered.push(path);
        }
      }
    }
    let imported = await importIndex(recovered);
    return imported;
  };

  Load();

  return {
    "put": Put,
    "get": Get,
    "del": Del,
    "list": List,
    "importDB": importDB,
    "exportDB": exportDB,
    "deleteDB": deleteDB,
    "importIndex":importIndex,
    "exportIndex":exportIndex,
    "saveIndex":saveIndex,
    "deleteIndex":deleteIndex,
    "recoverIndex":recoverIndex,
    "onEvent": datastore.onEvent,
    "hashPath": hashPath,
    "raw": datastore
  };

}

if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = CryptoDB;
}
