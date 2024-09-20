FROM python:3.8

WORKDIR /pipa_back 

COPY requirements.txt .

RUN pip install --upgrade pip && pip install -r requirements.txt

RUN apt-get update && apt-get install -y firefox-esr 


ENV GECKODRIVER_VERSION 0.34.0
ENV GECKODRIVER_DIR /geckodriver
RUN mkdir $GECKODRIVER_DIR

RUN wget -q --continue -P $GECKODRIVER_DIR "https://github.com/mozilla/geckodriver/releases/download/v$GECKODRIVER_VERSION/geckodriver-v$GECKODRIVER_VERSION-linux64.tar.gz"
RUN tar -xzf $GECKODRIVER_DIR/geckodriver-v$GECKODRIVER_VERSION-linux64.tar.gz -C $GECKODRIVER_DIR


RUN apt-get update 
RUN apt-get install -y --no-install-recommends curl  
RUN rm -rf /var/lib/apt/lists/*

# RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s

# RUN trivy filesystem --exit-code 1 --no-progress / 


ENV PATH $GECKODRIVER_DIR:$PATH

COPY . .

EXPOSE 5000

ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:5000", "server:app"]
