import * as fs from 'fs';
import archiver from 'archiver';

export default class Zipper {
	async zipDirectory(srcDir: string, targetPath: string): Promise<any> {
		try {
			return new Promise<any>((fulfill, reject) => {
				const zipOutput = fs.createWriteStream(targetPath);
				const archive = archiver('zip', {zlib: {level: 9}});

				archive.on('warning', function (err: any) {
					if (err.code === 'ENOENT') {
						console.log(err);
					} else {
						// throw error
						throw err;
					}
				});

				archive.on('error', function (err: any) {
					throw err;
				});

				zipOutput.on('close', function () {
					console.log('Archiver:: INFO ' + archive.pointer() + ' total bytes');
					console.log('Archiver:: INFO Archiver has been finalized and the output file descriptor has closed.');
					fs.readFile(targetPath, 'base64', function (err) {
						if (err) {
							console.log('Archiver:: ZipFile fs.readFile ERROR ' + err);
							reject(err);
						} else {
							fulfill();
						}
					});
				});

				archive.on('error', function (err: any) {
					console.log('Archiver:: ERROR ' + err);
					reject(err);
				});
				archive.pipe(zipOutput);
				archive.directory(srcDir, false);
				archive.finalize();
			});
		} catch (err) {
			console.log('Archiver:: zipDirectory() ERROR ' + err);
		}
	}
}