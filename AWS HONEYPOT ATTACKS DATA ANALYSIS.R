
#Set As Working Directory
setwd("~/AIT 582/aws-honeypot-attack-data")

#loading required packages 
library(ggplot2)
library(dplyr)
library(RColorBrewer)
library(rworldmap)
library(ggthemes)
library(plotly)
library(randomForest)
library(plyr)
library(readr)
library(rpart)
library(rpart.plot)
library(lubridate)
library(knitr)
library(plotrix)
library(MASS)
library(class)
library(ISOweek)
library(stringr)

#Importing the dataset
HP<-read.csv('AWS_Honeypot_marx-geo.csv',sep=',',stringsAsFactors=F)
HP %>% dplyr::filter(latitude>100) %>% dplyr::select(srcstr, country, locale, latitude, longitude) %>% head(10)

#Data Preprocessing 
# cleanup the missing geo locations
HP1<- data.frame(HP %>% filter(!is.na(latitude) & !is.na(longitude)))
# filter the wrong coded latitude
dfc1 <-data.frame(HP1 %>% filter(latitude>100))
dfc2 <-data.frame(HP1 %>% filter(latitude<=100))

# switch the X ad latitude column
dfc1$latitude <- dfc1$X
# re-rbind the subsets
attackloc <- data.frame(rbind(dfc2,dfc1))
# remove the now useless X column
attackloc$X<-NULL

#Setting a Reference data
RES <- data.frame(attackloc %>% 
                    dplyr::group_by(srcstr,country, longitude, latitude, locale) %>% 
                    dplyr::summarize(count=n()) %>% arrange(-count))

# select the top bad IP.adresses and make a new name to identify unique location: IP.adress + location
topattacks<-data.frame(RES %>% top_n(10))
topattacks$fullIP <-paste0(topattacks$srcstr,'(',topattacks$locale,')')
topattacks

#Removing all the unneccesary feilds
RES1 <- data.frame(HP1%>% 
                     dplyr::group_by(datetime,host,src,proto,country, longitude, latitude, locale) %>% 
                     dplyr::summarize(count=n()) %>% arrange(-count))
RES1

RES1 %>% 
  mutate(
    datetime = datetime %>% parse_date_time(order = "%m/%d/%y %H:%M"),
    host= host %>% as.factor, 
    proto = proto %>% as.factor, 
    country = country %>% as.factor,
    lmp_country = country )
head(RES1)
sum(is.na(RES1))

#pie chart for protocols used
fig1 <- plot_ly(HP1,type='pie', labels= ~proto, 
                textinfo='label+percent',
                insidetextorientation='radial')%>% layout(title = 'Name Of Packet Protocal Type used By Attacker')

fig1

#Most attacks for Protocol type.
TableP<-table(HP1$proto)
summary(TableP)
TableP

#hypothesis tests
t.test(HP1$spt,HP1$dpt)
t.test(HP1$latitude,HP1$latitude)

#test to determine factor relationship
chisq.test(HP1$host,HP1$proto)

chisq.test(table(HP1$country))

chisq.test(HP1$country,HP1$proto)

#table for country and time of attack
TableT<-table(HP1$country,HP1$datetime)
head(TableT,10)

#Analyzing which country has the highest effected ports.
HPF<- HP1[-c(1,5,9,11,12,13,14,15,16)]
head(HPF)

summary(HPF)
sum(is.na(HPF))

Destinationport<-HPF[,"dpt"]!=0
Sourceport<-HPF[,"spt"]!=0
Ports<-!Destinationport & !Sourceport
Ports

#displaying high ports presence for countries
CountryNames<-HPF[,7]
CountryNames
CountryN<-sub("","_",CountryNames)
names(Ports)<-CountryN
PortD<-sapply(Ports,function(x) if(1) "Ports" else "Port Not Available")
PortD
max(HPF$country)

# Geographical location of the attacks 
#Displaying the attacked areas with colour brewer and map data.
histo<-ggplotGrob(
  topattacks %>% ggplot(aes(x=reorder(fullIP,count),y=count)) + 
    geom_bar(stat='identity') + coord_flip() + theme_fivethirtyeight() + 
    theme(axis.text=element_text(size=5)) + labs(subtitle='top 10 bad IP addresses'))
histo

countries_map <-map_data("world")
world_map<-ggplot() + 
  geom_map(data = countries_map, map = countries_map,aes(x = long, y = lat, map_id = region, group = group), fill = "green", color = "white", size = 0.1) + 
  theme_minimal() + 
  theme(axis.text=element_blank())

world_map + 
  geom_point(data=RES,aes(x=longitude,y=latitude,size=count,color=count),alpha=.7) +
  scale_color_gradient2(name='',low = "#AA4371", mid = "blue", high = "orange") + 
  guides(color=FALSE,size=F) + 
  scale_radius(range=c(1,20)) + 
  labs(title=' Attackers IP Address Locations Identified by AWS Honey pot',
       subtitle=' April-2013 to August-2013',x='longitude',y='latitude') + 
  annotation_custom(grob = histo, xmin = 80, xmax = 210, ymin = -100, ymax = -40)
summary(RES1)

# Returning timedate into splits of time,day,month and year
attackloc$month<-sapply(attackloc$datetime,function(x) as.numeric(strsplit(strsplit(x,' ')[[1]][1],'/')[[1]][1]))
attackloc$day<-sapply(attackloc$datetime,function(x) as.numeric(strsplit(strsplit(x,' ')[[1]][1],'/')[[1]][2]))
attackloc$year<-2000 + sapply(attackloc$datetime,function(x) as.numeric(strsplit(strsplit(x,' ')[[1]][1],'/')[[1]][3]))
attackloc$hour<-sapply(attackloc$datetime,function(x) as.numeric(strsplit(strsplit(x,' ')[[1]][2],':')[[1]][1]))
attackloc$min<-sapply(attackloc$datetime,function(x) as.numeric(strsplit(strsplit(x,' ')[[1]][2],':')[[1]][2]))
attackloc$DateTS<-as.POSIXct(
  paste0(attackloc$year,'-',
         attackloc$month,'-',
         attackloc$day,' ',
         attackloc$hour,':',
         attackloc$min,':00'),format= "%Y-%m-%d %H:%M:%S")

topIPaddress<-topattacks$srcstr
attackers<- data.frame(attackloc%>% dplyr::filter(srcstr %in% topIPaddress))
attackers
max(attackers$srcstr)
max(attackers$src )
max(attackers$country )
max(attackers$locale )
max(attackers$datetime )
max(attackers$host )
max(attackers$proto )

#Displaying some of the maximum Observations in each feild
cat("The main attacked Source IPaddress and packet are",max(attackers$srcstr), "and", max(attackers$src ))
cat("The main attacked Country and locale are",max(attackers$country), "and", max(attackers$locale ))
cat("The main attacked Host and Protocal used are",max(attackers$host ), "and", max(attackers$proto ))

#Time analysis on Top attackers IP addresses
lims <- as.POSIXct(strptime(c("2013-03-01 00:00:00","2013-10-01 23:59:59"), format = "%Y-%m-%d %H:%M:%S"))
attackers %>% 
  dplyr::select(year, month, day, srcstr) %>% 
  mutate(dd = as.POSIXct(as.Date(paste0(year,'-',month,'-',day), format= "%Y-%m-%d"))) %>%
  dplyr::group_by(srcstr,dd) %>% 
  dplyr::summarize(count=n()) %>% 
  ggplot(aes(x=dd,y=count,group=1)) + geom_histogram(stat='identity',aes(group=1)) + 
  theme_gray() + labs(title= 'Month and Day wise Top Attackers IPaddress ',x='Time Period',y='Attacks Count')+
  scale_x_datetime(limits =lims) + facet_wrap(~srcstr, ncol=2, scales='free')

#Additional Visuals on honeypot host to Detect the attack trends
attackloc %>% dplyr::select(year, month, day, host)%>% 
  mutate(dd = as.POSIXct(as.Date(paste0(year,'-',month,'-',day), format= "%Y-%m-%d"))) %>%
  dplyr::group_by(host,dd)%>% 
  dplyr::summarize(count=n()) %>% 
  ggplot(aes(x=dd,y=count,group=host,fill=host)) + geom_histogram(stat='identity',aes(group=host)) + 
  theme_dark() + facet_wrap(~host,scales='free',ncol=2) +
  theme(legend.position='left',legend.direction='vertical',strip.text.x = element_text(size=0)) +
  labs(title='Detection by Attacks on Hosts',x='Time Period',y='Attacks Recorded',legend='Host Names')

#list of Unique observations 
unique(RES1$country)
unique(RES1$host)
unique(RES1$proto)
unique(RES1$locale)

RES1$full_ip<- paste(RES1$country,RES1$locale,RES1$src,sep="-")
RES1$full_ip_t<-paste(RES1$country,RES1$locale,RES1$src,RES1$datetime,sep="-")

#Some Unique Observations in the data.
Uniquehost<- unique((RES1$host))
uniqueScr<- unique(RES1$full_ip_t)
head(Uniquehost)
sample(uniqueScr,20)

mod2 <- glm(data=RES1,count ~ country + locale + proto+ host )

#summary
summary(mod2)

#significance and confidence level of model fit
sigma(mod2)*10/mean(RES1$count)
confint.lm(mod2)

#Train data set for prediction
#Split data into train and test set
set.seed(1)
train <-sample(0.05:length(RES1$count), length(RES1$count)*0.05)
test <- sample(0.1:length(RES1$count), length(RES1$count)*0.1)

RES1.train <- RES1[train,]
RES1.test <- RES1[test,]
str(RES1)
unique(RES1)
dim(RES1)
dim(RES1.test)
dim(RES1.train)
summary(RES1.test)
summary(RES1.train)
#Visualizing location(country and locale) wise source and time.
str(RES1$full_ip)
str(RES1$full_ip_t)

#Logistic Regression
bestmodel<-glm(count~ host+src+proto,data=RES1.train,family = binomial)
#best fit
mylogit.probs1<-predict(bestfit,validation,type="response")
mylogit.pred2[mylogit.probs1 >0.5] = "most attacks"
table(mylogit.pred2, RES1.train$count)
#accuracy 73.90%
#We Found that in the initial fit the model had accuracy below 30 and after the prediction it is seen 
#that most of the attackers use common IP feilds for frequent attacks on host from a specific location.
#The probability of single attacks is also high as there are many hackers.
#we have fit a best statistic analysis and data exploration from initial data not providing any results 
#to unique observances.

#R couldnot not run our RF observations due to the memory and dataset comprise 
#So we could only fit logistic regression and linear model in R
#We made Use of Knime tool for Random Forest and Classification and found nearly 500 distint trees.
#The highest accuracy using R was found to be 81%.












