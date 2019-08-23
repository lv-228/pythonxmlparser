# -*- coding: utf-8 -*-

from lxml   import objectify
from sys    import exit, argv as consoleArg
from urllib import urlopen    as downloadFile
from json   import dumps
import re

class xmlToJson:
	errors = {

'hrefError' :

"""
***
Ошибка! Первый параметр ожидается ссылка на xml файл вида (https://)(domain)/[path](filename.xml)
***
""",

'argCountError':

"""
***
Ошибка! Функция принимает 3 параметра: действие (parse или test), ссылку на файл xml формата, путь для записи данных в файл (опционально)
***
""",

'fileFormatError':

"""
***
Ошибка! Не верный формат файла
***
""",

'commandNotFoundError':

"""
***
Ошибка! Команда не найдена!
***
"""
}

	criteria = []
	answer   = []
	fileName = ''

	#Позволяет вызвать функцию без создания объекта класса
	#@classmethod
	def parseXmlToJson():
		xmlToJson.argvCheck(consoleArg)
		xmlToJson.getData()
		if len(consoleArg) == 4:
			xmlToJson.fileName = consoleArg[3]
			xmlToJson.saveJsonDataInFile(dumps(xmlToJson.answer), xmlToJson.fileName)
		else:
			print(dumps(xmlToJson.answer))

	@classmethod
	def argvCheck(self, userArgvs):
		if len(userArgvs) > 1 and len(userArgvs) <= 4:
			regHref     = re.match(r'^https://\S+[.]xml$', userArgvs[2])
			errors = []
			errors.append((xmlToJson.errors['hrefError'] if regHref is None else ''))
			if len(userArgvs) == 4:
				regFilePath = re.match(r'^\S+[.](json|txt)$', userArgvs[3])
				errors.append((xmlToJson.errors['fileFormatError'] if regFilePath is None else ''))
				if xmlToJson.errors['hrefError'] in errors:
					print(xmlToJson.errors['hrefError'])
					exit(0)
				if xmlToJson.errors['fileFormatError'] in errors:
					print(xmlToJson.errors['fileFormatError'])
					xmlToJson.createJsonDataFile()
		else:
			print(xmlToJson.errors['argCountError'])
		return True

	@classmethod
	def getCriteria(self, *args):
		for j, elem in enumerate(args[0].iterchildren()):
			if 'comment' in elem.attrib and elem.attrib['comment'] + ' ' + elem.getparent().attrib['operator'] not in xmlToJson.criteria:
				xmlToJson.criteria.append(elem.attrib['comment'] + ' ' + elem.getparent().attrib['operator'] if j + 1 < len(args[0].getchildren()) else ' ' + elem.attrib['comment'])
			if 'operator' in elem.attrib:
				parent = elem.getparent()
				if 'OR' in elem.attrib['operator'] and 'operator' in parent.attrib and parent.attrib['operator'] == 'AND':
					for val in elem.iterchildren():
						if xmlToJson != [] and xmlToJson.criteria[len(xmlToJson.criteria) - 1] != parent.getchildren()[0].attrib['comment'] + ' ' + elem.getparent().attrib['operator']:
							xmlToJson.criteria.append(parent.getchildren()[0].attrib['comment'] + ' ' + elem.getparent().attrib['operator'])
						for i, qwe in enumerate(val.iterchildren()):
							if 'comment' in qwe.attrib and xmlToJson != []:
								xmlToJson.criteria[len(xmlToJson.criteria) - 1] += ' ' + qwe.attrib['comment'] + ' ' + parent.attrib['operator'] if i + 1 < len(val.getchildren()) else ' ' + qwe.attrib['comment']
				#self.getCriteria(elem)

	@classmethod
	def commandCheck(self,userArgvs):
		if userArgvs[1] not in xmlToJson.commands.keys():
			raise parserException(xmlToJson.errors['commandNotFoundError'])

	@classmethod
	def objectifyToList(self, objf):
		myid       = objf.attrib['id']
		title      = objf.metadata.title
		data       = list(map(str, str(objf.metadata.advisory.issued.attrib['date']).split('-')))
		dataFormat = data[2] + '.' + data[1] + '.' + data[0]
		cve_list = []
		rhsa_id  = []
		for ref in objf.metadata.reference:
			if ref.attrib['source'] == "RHSA":
				rhsa_id.append(ref.attrib['ref_id'])
			if ref.attrib['source'] == "CVE":
				cve_list.append(ref.attrib['ref_id'])
		links = []
		for child in objf.metadata.advisory.getchildren():
			if 'href' in child.attrib:
				links.append(child.attrib['href'])
		criteria = objf.criteria
		xmlToJson.getCriteria(criteria)
		xmlToJson.answer.append({'id': myid, 'title': str(title), 'issued': dataFormat, 'rhsa_id': rhsa_id, 'cve_list': cve_list, 'links': links, 'criteria': xmlToJson.criteria})
		xmlToJson.criteria = []

	@classmethod
	def createJsonDataFile(self):
		positivePattern = ['Д', 'д', 'Y', 'y']
		negativePattern = ['Н', 'н', 'N', 'n']
		userAnswer = False
		while userAnswer != True:
			try:
				a = raw_input('Создать файл с форматом JSON?[Д/н]\n')
				if a in positivePattern:
					userAnswer = True
				if a in negativePattern:
					secAnswer = False
					while secAnswer != True:
						b = raw_input('Вывести JSON в консоль?[Д/н]\n')
						if b in positivePattern:
							secAnswer = True
							xmlToJson.getData()
							print(dumps(xmlToJson.answer))
						if b in negativePattern:
							secAnswer = True
							print('Невозможно записать данные в файл!')
					exit(0)
			except KeyboardInterrupt:
				print('\nНеизвестная ошибка ввода. Файл не был создан!')
				exit(0)
		xmlToJson.fileName = consoleArg[3] + '.json'

	@classmethod
	def saveJsonDataInFile(self, jsonData, fileName):
		with open(fileName, 'w') as file:
			file.write(jsonData)

	@classmethod
	def getData(self):
		binaryData = downloadFile(consoleArg[2]).read()
		xml        = objectify.fromstring(binaryData)
		for defenition in xml.definitions.getchildren():
			xmlToJson.objectifyToList(defenition)


	#Хранит доступные команды как ключь, вызывает необходимую функцию по значению
	commands = {'parse' : parseXmlToJson}

class parserException(Exception):
	def __init__(self, text):
		self.txt = text

obj = xmlToJson()
try:
	obj.commands[consoleArg[1]]()
except KeyError:
	print(xmlToJson.errors['commandNotFoundError'])
except IndexError:
	print('Ошибка! Минимальное количество параметров 2 (команда, ссылка на xml файл)')
#xmlToJson.parseXmlToJson()