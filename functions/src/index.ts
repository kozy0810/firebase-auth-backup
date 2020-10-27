import * as kms from '@google-cloud/kms';
import * as storage from '@google-cloud/storage';
import * as admin from "firebase-admin";
import * as functions from "firebase-functions";
import * as fs from "fs";

// 型定義がないため require でインポート
const firebaseTools = require("firebase-tools")

const region = "asia-northeast1";

admin.initializeApp();

function getProjectId() {
  const projectId = admin.instanceId().app.options.projectId;
  if (!projectId) {
    throw Error('projectId not exist.')
  }
  return projectId
}

export const backupFirebaseAuthentication = functions
  .region(region)
  .pubsub
  // 毎日深夜 3 時
  .schedule('0 3 * * *')
  .timeZone('Asia/Tokyo')
  .onRun(async (context) => {
    const projectId = getProjectId()
    const bucketName = `${projectId}-firebase-auth-backup-bucket`

    const now = new Date()
    const timestamp = now.getFullYear()
      + ('0' + (now.getMonth() + 1)).slice(-2)
      + ('0' + now.getDate()).slice(-2)
      + '-' + ('0' + now.getHours()).slice(-2)
      + ('0' + now.getMinutes()).slice(-2)
      + ('0' + now.getSeconds()).slice(-2)
    const plaintextFileName = `firebase-authentication-backup-${timestamp}.json`

    const tmpDir = '/tmp'
    const tmpPlaintextFileName = `${tmpDir}/${plaintextFileName}`
    console.log(`tmpPlaintextFileName = ${tmpPlaintextFileName}`)
    const tmpCiphertextFileName = `${tmpDir}/${plaintextFileName}.encripted`
    console.log(`tmpCiphertextFileName = ${tmpCiphertextFileName}`)

    const gcsDestination = `${now.getFullYear()}/${('0' + (now.getMonth() + 1)).slice(-2)}/${plaintextFileName}.encripted`

    // ローカルに取得
    await firebaseTools.auth.export(tmpPlaintextFileName, { project: projectId, exportOptions: "json"})

    // ファイル読み込み
    const plaintext = fs.readFileSync(tmpPlaintextFileName)

    // 暗号化
    const kmsClient = new kms.KeyManagementServiceClient()
    const keyName = kmsClient.cryptoKeyPath(projectId, region, 'my-keyring', 'firebase-authentication-backup-key')
    const [result] = await kmsClient.encrypt({ name: keyName, plaintext })
    if (!result.ciphertext) {
      console.error(`result.ciphertext = ${result.ciphertext}`)
      return
    }
    fs.writeFileSync(tmpCiphertextFileName, result.ciphertext)

    // GCS に保存
    const gcsClient = new storage.Storage()
    const bucket = gcsClient.bucket(bucketName)
    await bucket.upload(tmpCiphertextFileName, { destination: gcsDestination })

    // ローカルのファイルを削除
    fs.unlinkSync(tmpPlaintextFileName)
    fs.unlinkSync(tmpCiphertextFileName)
  })